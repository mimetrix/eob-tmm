#!/usr/bin/env python3
"""Decode the tracepoint's shared-memory segment --- the drain agent's read path.

This is what a NATS/ZeroMQ publisher would do before publishing: map the segment,
walk each ring, decode records. It shares NOTHING with TMM but the bytes --- no
loader socket, no counters, no eBPF program --- which is the whole point of the
shared-memory design and the reason this script is the honest test of it.

It reads a COPY of the segment rather than mapping the live one, because the
production image has no Python. Pull the copy with dd (see --help epilog). A real
agent maps it directly and follows producer_pos.

WHAT IT DOES NOT DO. It does not advance consumer_pos. A real drain must, or a
STREAM ring fills and starts counting drops --- reading without acknowledging is
fine for inspection and wrong for a consumer.

Layouts come from substrate/ls_tp_ring.h and ls_ring.h. They are transcribed
here, which is the same fragility the tracepoint itself had to unlearn: the
_Static_assert on the C side and the geometry checks below are what keep a
silent divergence from turning into plausible-looking garbage.
"""
import argparse
import struct
import sys

SEG_MAGIC = 0x4C53534547303031          # "LSSEG001"
SEG_HDR   = 32                          # struct ls_tp_seg
RING_HDR  = 56                          # struct ls_ring
REC_HDR   = 32                          # struct ls_rec (24 + ts_ns)
RING_BUSY    = 1 << 31
RING_DISCARD = 1 << 30
RING_LENMASK = ~(RING_BUSY | RING_DISCARD) & 0xFFFFFFFF

# The 40-byte tmm:l7:http_headers record, in order. Bump alongside
# LS_TP_SCHEMA_HTTP whenever this changes shape.
SCHEMA_HTTP = 2          # bumped with ts_ns
SEG_VERSION = 2
HOOKS = {1: "http1", 2: "http2", 3: "http3"}
HTTP_FIELDS = ["parse_err", "err", "reject_reason", "passthru", "version", "method",
               "header_count", "status_code", "invalid_flags", "body_pos",
               "hdr_bytes"]

VERSION  = {0: "UNKNOWN", 1: "HTTP/0.9", 2: "HTTP/1.1", 3: "HTTP/1.0"}
INVALID  = [(0x01, "method"), (0x02, "scheme"), (0x04, "path"),
            (0x08, "status"), (0x10, "authority")]


def decode_http(vals):
    d = dict(zip(HTTP_FIELDS, vals))
    d["version_name"] = VERSION.get(d["version"], f"?{d['version']}")
    d["invalid_names"] = ",".join(n for b, n in INVALID if d["invalid_flags"] & b) or "-"
    return d


def main():
    ap = argparse.ArgumentParser(
        description="Decode a tracepoint shared-memory segment.",
        epilog="Pull a segment out of a running pod first:\n"
               "  POD=$(kubectl get pods -l app=f5-tmm --no-headers | grep Running "
               "| awk '{print $1}' | head -1)\n"
               "  kubectl exec $POD -c f5-tmm -- dd if=/tmp/ls_tp_ring bs=4096 "
               "2>/dev/null > seg.bin\n"
               "  ls_tp_dump.py seg.bin",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("segment")
    ap.add_argument("-n", "--max", type=int, default=10,
                    help="records to print per ring (default 10; 0 = all)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="totals only")
    a = ap.parse_args()

    d = open(a.segment, "rb").read()
    if len(d) < SEG_HDR:
        sys.exit(f"*** {a.segment}: {len(d)} bytes --- too small to be a segment")

    magic, ver, n_rings, stride, dsz, claimed = struct.unpack_from("<QIIIII", d, 0)
    if magic != SEG_MAGIC or (ver and ver != SEG_VERSION):
        if magic == SEG_MAGIC:
            sys.exit(f"*** segment is format version {ver}, this decoder speaks "
                     f"{SEG_VERSION}. ls_rec changed size, so walking it would decode "
                     f"garbage at a plausible-looking stride. Rebuild one side.")
    if magic != SEG_MAGIC:
        sys.exit(f"*** not a tracepoint segment (magic {magic:#x}).\n"
                 f"    An all-zero file here usually means the sidecar mapped its OWN\n"
                 f"    /dev/shm instead of a shared emptyDir --- which looks like\n"
                 f"    'no traffic' rather than a misconfiguration.")

    # Geometry, checked rather than trusted: a wrong stride walks into the middle
    # of a ring and decodes plausible nonsense.
    if dsz & (dsz - 1):
        sys.exit(f"*** data_size {dsz} is not a power of two; ring masking is invalid")
    if stride != RING_HDR + dsz:
        sys.exit(f"*** stride {stride} != {RING_HDR}+{dsz}; layout mismatch with ls_tp_ring.h")
    need = SEG_HDR + n_rings * stride
    if len(d) < need:
        sys.exit(f"*** truncated: {len(d)} bytes, need {need}")

    print(f"segment  version={ver}  rings={n_rings}  data={dsz}  claimed={claimed}")

    total = drops = 0
    for i in range(n_rings):
        base = SEG_HDR + i * stride
        (_m, _v, pol, rdsz, _p, prod, cons, dr, db) = struct.unpack_from("<QIIIIQQQQ", d, base)
        drops += dr
        if prod == 0 and dr == 0:
            continue
        data = base + RING_HDR
        recs, off = [], 0
        while off < prod and off < rdsz:
            (hdr,) = struct.unpack_from("<I", d, data + off)
            if hdr & RING_DISCARD:                 # wrap padding
                off += 8 + (hdr & RING_LENMASK)
                continue
            if hdr & RING_BUSY:                    # producer mid-write; stop here
                break
            body = hdr & RING_LENMASK
            if body == 0:
                break
            hook, schema, seq, tmm, ln, ts = struct.unpack_from("<IIQIIQ", d, data + off + 8)
            payload = data + off + 8 + REC_HDR
            recs.append((seq, hook, schema, tmm, ln, payload, ts))
            off += (8 + REC_HDR + ln + 7) & ~7
        total += len(recs)
        print(f"\nring {i}  producer={prod} consumer={cons} drops={dr} "
              f"policy={'STREAM' if pol == 0 else 'RECORD'}  records={len(recs)}")
        if a.quiet:
            continue
        for (seq, hook, schema, tmm, ln, off_p, ts) in (recs if a.max == 0 else recs[:a.max]):
            if schema == SCHEMA_HTTP and ln == 44:
                f = decode_http(struct.unpack_from("<11I", d, off_p))
                import datetime as _dt
                when = _dt.datetime.fromtimestamp(ts / 1e9).strftime("%H:%M:%S.%f")[:-3]
                print(f"  {when} seq={seq:<5} {HOOKS.get(hook,'?'):5} tmm={tmm} {f['version_name']:8} "
                      f"method={f['method']:<3} hdrs={f['header_count']:<3} "
                      f"parse_err={f['parse_err']:<3} err={f['err']:<3} "
                      f"class={'normal' if f['parse_err'] not in (3,5,16) else ('waived' if f['passthru'] else 'refused')}")
            else:
                print(f"  seq={seq:<5} tmm={tmm} hook={hook} schema={schema} len={ln} "
                      f"(no decoder --- raw)")

    print(f"\nTOTAL {total} record(s), {drops} drop(s)")
    if drops:
        print("  drops are COUNTED, never silent: a STREAM ring full means the consumer\n"
              "  is not keeping up. The data plane never waited on it.")


if __name__ == "__main__":
    main()
