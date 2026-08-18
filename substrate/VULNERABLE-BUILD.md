# `tmm:vuln-alpn` — a deliberately vulnerable build

> **RETIRED 2026-08-18. The revert is no longer in the build tree.** The BNK demo
> dropped shielding entirely --- CVE work moved to classic BIG-IP, and shielding an
> internal non-CVE finding was judged marginal as a business claim, so there is no
> longer any reason to carry the defect. `git checkout
> src/modules/hudfilter/ssl/ssl.c` has been run on the build box; the bounds check
> is back and `git status` there is clean for that file. `alpn_guard.bpf.c` is kept
> as a working artifact (PREVAIL passes it; the object has zero backward jumps, so
> its loop really is unrolled) but nothing demos it.
>
> This page stays as the record of what was done and why, and as the handling rules
> if the defect is ever reintroduced. **Do not reintroduce it without re-reading the
> handling rules below.**

**This image contains a known security defect on purpose. It exists to validate a
mitigation and must never be deployed anywhere but the lab cluster.**

## What was removed

Commit `c806f1b2e8` ("batch 2 security fixes — app", `BZ-2407289`, `BZ-2407329`,
2026-07-28) added twelve lines to `ssl_alpn_match()` in
`src/modules/hudfilter/ssl/ssl.c`. Those twelve lines are reverted in this build,
and nothing else is:

```c
/* Validate that the protocol entry length byte does not
 * extend past the extension buffer. A zero length is also
 * invalid per RFC 7301. */
if ((alpn_ext[alpn_ext_ix] == 0) ||
        (alpn_ext_ix + 1 + alpn_ext[alpn_ext_ix] > alpn_ext_sz)) {
    ssl_tracef(sc, "malformed ALPN extension entry at offset %d\n", alpn_ext_ix);
    alpn_ext_ix = alpn_ext_sz;
    break;
}
```

Without them the loop walks the ALPN list using each entry's own length byte as
the stride, with no check that the entry stays inside the extension. A crafted
length runs the index past `alpn_ext_sz` and the `memcmp` below reads out of
bounds. **The length byte comes from the client's TLS ClientHello**, so the input
is entirely attacker-controlled and reaches this code before any authentication.

## Why a regressed build rather than a live CVE

Four candidate sets were screened against the running cluster and every one was
unreachable: `hudproxy/memcached` (6 findings), `hudfilter/http/http_psm.c` (6),
`hudfilter/quic` (12). All are compiled into the BNK binary and all sit behind
configuration BNK does not expose — `fired=0` under traffic in each case,
measured, not assumed.

The reason is a sampling problem, not a property of the mechanism. Those bugs
come from static-analysis sweeps of the **classic BIG-IP** tree
(`TMOS-bigip17.1.3.2-*`, `BIGIP-tmos-source-*`), and findings cluster in
rarely-exercised code precisely because nobody found them by running it. BNK
executes a narrow slice: TLS, TCP, HTTP/1.x, the proxy core.

`ssl_alpn_match` is the first candidate on a path BNK genuinely runs. Its fix is
already in `main`, so the only way to demonstrate a mitigation against it is to
put the defect back.

## Handling rules

- Tag is `tmm:vuln-alpn`. **Never** `tmm:local`, `tmm:tpN`, or anything that
  reads as a normal build.
- Lab cluster only. Never pushed to a registry.
- The revert lives in the build box working tree and is **not committed** to the
  TMM tree. `git status` there shows one modified file; restoring is
  `git checkout src/modules/hudfilter/ssl/ssl.c`.
- Any result produced on this image states that it ran on a regressed build.
  A mitigation demonstrated here shows the **mechanism** works. It is not
  evidence that a shipped release was vulnerable — the shipped release has the
  fix.

## What the shield has to express

The check is a bounded predicate over attacker-controlled bytes, which is the
shape PREVAIL admits — but not trivially. `alpn_ext` and `alpn_ext_sz` are
derived from `sc`, not passed as arguments, so the host builder has to lift them
into a flat ctx before the program runs. The program then walks entries with a
**constant** iteration bound; PREVAIL will not accept a loop bounded by an
attacker-supplied length, which is the same property the original code got wrong.
