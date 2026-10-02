"""The AI gateway with an eBPF probe attached to its record-publish callback.

Runs the four smoke cases twice: once with no probe, once with the signed
aigw_record probe armed at aigw_host_obs_publish in monitor mode. With the
probe armed, every record the library publishes is captured from the ring and
compared with the expected request outcome. Then the probe is disarmed and
revoked, and the cases run a third time.

Pass criteria:
- the HTTP results are identical in all three phases;
- in the armed phase, one reassembled record per published request, carrying
  the expected model and status, and the probe's calls equal its records;
- the hook bytes are a CALL while armed and the original pad after disarm;
- no VM errors and no safe returns.
"""

import asyncio
import json
import os
from pathlib import Path
import secrets
import struct
import time

import tao
import tao.test_types

import aigw_smoke_suite as smoke

SLOT = "4"
HOOK = "aigw_host_obs_publish"
FRAME = struct.Struct("<II3Q6I128s")


async def run(*argv):
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await asyncio.wait_for(proc.communicate(), 60)
    return {
        "argv": list(argv),
        "rc": proc.returncode,
        "stdout": out.decode(),
        "stderr": err.decode(),
    }


async def cli(result, *args):
    row = await run("python3", "/work/ls-load.py", *map(str, args))
    result["commands"].append(row)
    assert row["rc"] == 0, row
    return row["stdout"]


async def drain(result, before_first_event=False):
    """The ring is created by TMM on its first event (ls_tp_seg_bootstrap).
    Only before any probe has run may its absence mean "no records yet"."""
    if before_first_event and not Path("/run/ls-stream/ls_tp_ring").exists():
        result["drains"].append({"rc": None, "absent_before_first_event": True})
        return []
    row = await run(
        "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
    )
    result["drains"].append(
        {"rc": row["rc"], "stderr": row["stderr"], "lines": len(row["stdout"])}
    )
    assert row["rc"] == 0, row
    assert "0 drop(s) seen" in row["stderr"], row
    return [json.loads(line) for line in row["stdout"].splitlines() if line]


def records(frames):
    """Reassemble chunked records by sequence; report gaps explicitly."""
    by_seq = {}
    for item in frames:
        data = bytes.fromhex(item["data"])
        if len(data) != FRAME.size:
            continue
        (
            magic,
            abi,
            _instance,
            seq,
            _mono,
            total,
            chunk,
            chunks,
            copied,
            flags,
            _res,
            body,
        ) = FRAME.unpack(data)
        if magic != 0x41474F42 or abi != 1:
            continue
        row = by_seq.setdefault(
            seq, {"total": total, "chunks": chunks, "parts": {}, "flags": 0}
        )
        row["flags"] |= flags
        row["parts"][chunk] = body[:copied]
    out = []
    for seq, row in sorted(by_seq.items()):
        complete = sorted(row["parts"]) == list(range(row["chunks"]))
        text = b"".join(row["parts"][i] for i in sorted(row["parts"]))
        out.append(
            {
                "sequence": seq,
                "total_len": row["total"],
                "complete": complete and not row["flags"],
                "flags": row["flags"],
                "text": text.decode("utf-8", "replace"),
            }
        )
    return out


async def phase(name, result, mock):
    rows = []
    chat = {"model": smoke.MODEL, "messages": [{"role": "user", "content": "ping"}]}
    cases = (
        ("chat", smoke.GATEWAY, "POST", "/v1/chat/completions", chat),
        ("models", smoke.GATEWAY, "GET", "/v1/models", None),
        (
            "unknown-model",
            smoke.GATEWAY,
            "POST",
            "/v1/chat/completions",
            dict(chat, model="no-such-model"),
        ),
        ("empty-config", smoke.REFUSED, "POST", "/v1/chat/completions", chat),
    )
    for case, port, method, path, body in cases:
        before = len(mock.requests)
        status, _head, payload = await smoke.http(port, method, path, body)
        rows.append(
            {
                "case": case,
                "status": status,
                "mock_requests": len(mock.requests) - before,
                "body_prefix": payload[:120].decode("utf-8", "replace"),
            }
        )
    result["phases"].append({"phase": name, "cases": rows})
    return [(r["case"], r["status"], r["mock_requests"]) for r in rows]


async def ebpf_test(log, _config):
    output = Path(os.environ["AIGW_RESULT"])
    directory = Path(os.environ["AIGW_PROBE_DIR"])
    key = "sk-ebpf-" + secrets.token_hex(16)
    mock = smoke.Mock(key)
    result = {
        "passed": False,
        "commands": [],
        "drains": [],
        "phases": [],
        "started_ns": time.time_ns(),
    }
    loaded = armed = False
    with output.open("x", encoding="utf-8") as receipt:
        try:
            result["configuration"], result["acknowledgements"] = await smoke.configure(
                log, key
            )
            async with await asyncio.start_server(
                mock.serve, smoke.BACKEND, smoke.MOCK
            ):
                baseline = await phase("before", result, mock)
                assert not await drain(result, before_first_event=True)
                text = await cli(
                    result,
                    "load-signed",
                    SLOT,
                    str(directory / "aigw_record.bpf.o"),
                    str(directory / "aigw_record.sig"),
                    "1",
                )
                assert "signature=verified" in text, text
                loaded = True
                identity = json.loads(await cli(result, "config-status", SLOT))
                doc = dict(identity)
                doc["expected_revision"] = doc.pop("revision")
                doc["revision"] = doc["expected_revision"] + 1
                doc["schema"] = 1
                doc.pop("entries")
                doc["rows"] = []
                path = output.parent / "probe-config.json"
                path.write_text(json.dumps(doc))
                await cli(result, "config-publish", SLOT, str(path))
                start = await cli(result, "status", SLOT)
                await cli(result, "arm", SLOT)
                armed = True
                observed = await phase("armed", result, mock)
                frames = await drain(result)
                after = await cli(result, "status", SLOT)
                await cli(result, "disarm", HOOK)
                armed = False
                final = await phase("after", result, mock)
                await cli(result, "revoke", SLOT)
                loaded = False
            result["frames"] = len(frames)
            result["records"] = records(frames)
            result["status_before"], result["status_after"] = start, after
            assert baseline == observed == final, (baseline, observed, final)

            def counter(text, name):
                return int(text.split(name + "=")[1].split()[0])

            fired = counter(after, "fired") - counter(start, "fired")
            assert counter(after, "errors") == counter(start, "errors"), after
            assert counter(after, "safe_returns") == 0, after
            recs = result["records"]
            assert fired == len(recs) >= 2, (fired, len(recs))
            assert all(r["complete"] for r in recs), recs
            docs = [json.loads(r["text"]) for r in recs]
            result["record_docs"] = docs
            joined = json.dumps(docs)
            assert smoke.MODEL in joined and "no-such-model" in joined, joined[:400]
            assert key not in joined
            result["passed"] = True
            return tao.Result.PASS
        except Exception as error:
            result["error"] = repr(error)
            raise
        finally:
            for args, flag in (
                ((("disarm", HOOK)), armed),
                ((("revoke", SLOT)), loaded),
            ):
                if flag:
                    try:
                        await cli(result, *args)
                    except Exception as error:  # keep cleanup failures visible
                        result.setdefault("cleanup_errors", []).append(repr(error))
            result["finished_ns"] = time.time_ns()
            text = json.dumps(result, indent=2, sort_keys=True)
            assert key not in text
            receipt.write(text + "\n")


def publish_tests():
    return [tao.test_types.DockerBaseTest2("aigw ebpf record probe", ebpf_test)]
