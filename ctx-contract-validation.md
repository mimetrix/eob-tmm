# Context allocation fix — live validation, 2026-09-23

**MEASURED:** entry and exit hooks now supply the full 96-byte region that the
pinned PREVAIL tracing descriptor permits. Both paths ran signed, JIT-compiled
test programs on live HTTP traffic. This closes the allocation gap recorded in
[`CONTESTED-PREMISES.md` §17](CONTESTED-PREMISES.md#17--the-96-byte-context-ceiling-is-a-capacity-limit--true-and-it-is-also-a-gap-we-had-not-named).
**Added hot-path cost remains unmeasured.**

## Identity and provenance

| Item | Recorded value |
|---|---|
| Source | Working tree based on `cd969f5`, stamped **`cd969f5-dirty`** |
| Build host | `eob-bnk-build-01`, `10.145.37.36` |
| Bytecode compiler | clang-18 18.1.3; pinned PREVAIL in `~/eob-tmm-staged/ebpf-verifier/bin/prevail` |
| Image | `docker.io/library/tmm:CTX96-20260923` |
| Image index digest | `sha256:1a607811fac8709b2be8cc8c794666bbe90f73944d3c56ac2b7fc96d61c095ab` |
| Packaged and executing GNU build ID | `5c76bc3a6069d7aa2aea51d32b69a2742563ddc4` |
| Runtime SHA-256 | `e51d4d79b7dc39294c12e32b7da6d7fda79a0446720e4afb3cca79c09c0a40d7` |
| Cluster | `kind-vs` on `eob-bnk-datkube-01`, `10.145.40.193` |
| Pod | `f5-tmm-59696979b6-6xv8n`, UID `041de6aa-9680-4a01-a674-0364ef270a43` |
| Kubernetes container image ID | `sha256:b67d24abdc97b48babb94a9c942f24a7ea2e9d741039a1996eec19507dd0e5d1` |
| Executing ELF | `/proc/24/exe`; SHA-256 above; **no `.BTF` sections** |
| Signing-key public fingerprint | `92f1570cf65345d7` (first eight SHA-256 bytes) |
| Rollback image | `docker.io/library/tmm:CLEAN-NOBTF`, retained on both kind nodes |

The build-tree comparison was read before copying: the five changed runtime files
contained the intended fix; the generated public-key header was preserved. All
40 recorded tree changes were accounted for. The existing HTTP/2 CVE revert is
still part of this tree; the new image is **not** a CVE-fixed image (§16).

`bnk-stage.sh` verified the working-tree copy, `bnk-sync-substrate.sh` removed all
26 substrate objects, and `bnk-package.sh` cleared stale packaging artifacts.
Packaging exited 0, with source freshness and all 40 exported substrate functions
checked. Packaged-runtime disassembly, using addresses from its matching debug
package, showed:

- `ls_tramp_dispatch` at `0x147cfc0`: seven zero qwords from context offset 40;
  `edx=0x60` at the `ls_vm_call` call.
- `ls_fexit_leave` at `0x147d700`: six zero qwords from context offset 48;
  `edx=0x60` at the same call boundary.

The string-token step of `bnk-ship-image.sh verify` was **skipped**, because this
change adds no unique string. Disassembly supplied the change-specific check;
the inspected runtime, image runtime, and executing ELF had the same SHA-256.

Fresh packaged BTF was derived with `--btf-only`, kept on the build host, and used
to rebuild the standard programs: **13 verified/signed, one expected rejection,
zero unexpected results**. Nine programs had field relocations resolved; all 13
were stripped of BTF. Both context probes were separately verified and signed for
`build_min == build_max == 0x5c76bc3a`, with a **monitor** ceiling. Exit admission
accepted `http_parse_client_headers` against the packaged binary.

## What the live test observed

[`check_ctx_live.bpf.c`](substrate/check_ctx_live.bpf.c) reads every reserved
qword, returns 1 iff all were initially zero, then poisons every reserved qword
with `0x6374783936746169`. Entry tests offsets 40–95; exit tests 48–95. Arguments
and the exit return value are not written. Pinned-toolchain disassembly confirmed
the actual reads and writes through bytes 88–95.

**Falsifiers:** any nonzero tail on entry, a missing invocation, an execution
error, a non-200 response, a changed pod/container, or a pad that fails to restore
fails the test. Positive and negative verifier-boundary tests separately require
88–95 to pass and 96–103 to be refused for both hook kinds.

Final complete run, slot 0 at `http_parse_client_headers`, patch address `0xccc604`:

| Case | Generation | `fired` | `safe_returns` | Errors delta | HTTP |
|---|---:|---|---|---:|---|
| Entry | 3 | 96 → 128 | 96 → 128 | 0 | 32/32 returned 200 |
| Entry, disarmed | 3 | 128 → 128 | 128 → 128 | 0 | 8/8 returned 200 |
| Exit | 4 | 128 → 160 | 128 → 160 | 0 | 32/32 returned 200 |
| Exit, disarmed | 4 | 160 → 160 | 160 → 160 | 0 | 8/8 returned 200 |

Counters were already nonzero from earlier test attempts; **the deltas**, not the
totals, describe this run. Each hook's last eight samples reported `len=96` and
`verdict=1`. Entry samples contained the poison at offset 40; exit samples retained
the return value 0 at offset 40. After each disarm, reading `/proc/24/mem` showed
`90 90 90 90 90` restored. While armed, the same bytes began with `e8`. Both load
records reported `jit=1`. The pod UID, container ID and restart count remained
unchanged: **zero restarts**.

**Witness distinction:** verdicts, context samples and JIT-load records are SELF
evidence. HTTP responses are observed by curl; ELF identity and patched bytes are
read independently through `/proc`; Kubernetes supplies pod/container identity and
restart counts. This is not an independent proof of every JIT memory access.
`safe_returns` here counts a **test-success verdict in monitor mode**, not blocked
requests or CVE prevention. The raw timing counters are not a cost measurement.

## Test failures retained, rather than counted as passes

1. Before the rebuild, `:8081` refused connections. A differing client-neighbor MAC
   suggested stale ARP, but flushing it did **not** recover the listener. The new
   image rollout, controller restart and neighbor flush changed reachability; this
   sequence does not isolate which action recovered TCP.
2. The first pre-arm check then got `curl: (52) Empty reply from server`.
   `ask` returned no record. The same failure occurred at the backend's own
   `127.0.0.1:80`: its listener was `/tmp/h2backend.py`, the HTTP/2 CVE origin,
   while `http1-vs` expected HTTP/1. The successful context test therefore used
   [`ctx-contract-test.yaml`](env/k8s/ctx-contract-test.yaml): a dedicated HTTP/1
   origin at `22.22.22.113:18081` and VIP `11.11.11.99:18081`.
3. The first entry run passed its context checks but the driver incorrectly
   required `armed=0` after disarm. `ask 'armed=1'` returned the September 11
   record: this field is not evidence of patched text. Slot 0 has the same
   behavior; `revoke` sets mode 0 but does not clear the field or reclaim the VM.
   The corrected driver tests actual pad bytes and counter deltas, and requires
   mode 0 before reusing the test slot.
4. The next run passed both context cases but its final JIT-log assertion required
   `slot=0`. `ask` found no record for that assertion. `ls_vm_reload()` compiles in
   a spare slot (1 here), then publishes both `vm` and `jit_fn` to slot 0. The
   corrected assertion recognizes the preparation log; the final complete run
   above exited successfully.

## Reproduction and end state

After the normal stage → sync → package pipeline, on the build host:

```sh
sh ~/eob-tmm-staged/env/scripts/bnk-build-ctx-test.sh
```

Transfer `~/ctx96-probes/` and the driver plus `bnk-deliver-program.py` to the lab.
On datkube, after deploying the matching image, with JIT, samples and verbose load
logging enabled and slot 0 disabled:

```sh
kubectl apply -f env/k8s/ctx-contract-test.yaml
kubectl wait --for=condition=Ready pod/ctx-contract-test --timeout=90s
kubectl wait --for=condition=Programmed f5-virtualservers/ctx-contract-test --timeout=90s
# Warm the new listener; select one stable pod, and pass the full expected ID.
python3 env/scripts/bnk-test-ctx-contract.py "$POD" "$PROGDIR" "$BUILD_ID"
kubectl delete -f env/k8s/ctx-contract-test.yaml
```

The driver disarms and disables its programs. The temporary ConfigMap, Pod, pool
and virtual server were deleted after validation. The new image remains deployed,
`LS_VM_VERBOSE=1` remains enabled, and slot 0 ends at `mode=0`, `gen=4`, `fired=160`.
The shared `http1-vs`/HTTP/2-backend mismatch remains; successful HTTP results above
refer to the dedicated fixture, not `:8081`. Both VMs remained reachable by SSH.

**Limits:** one function, one stable pod, sequential HTTP/1 requests. No new
benchmark/self-test execution claim, saturation test, concurrency/quiescence proof,
or added per-call-cost measurement. The prior harness results cover saved-state
isolation and the full 96-byte overwrite; the live probes write the reserved tail.

## Cached receipts

Hashes are also in [`evidence/cache/MANIFEST.sha256`](evidence/cache/MANIFEST.sha256).

| File | SHA-256 |
|---|---|
| [`ctx96-package-20260923.log`](evidence/cache/ctx96-package-20260923.log) | `061ca2054d248a287a2cb2cd0a015941b9d85bb808c2bcbffbd16fb8af2a45c9` |
| [`ctx96-bake-20260923.log`](evidence/cache/ctx96-bake-20260923.log) | `89b3221cb3f0a6ac6de60f64fa555bf20c946a97989f09b3f74541a75e7b6945` |
| [`ctx96-live-20260923.log`](evidence/cache/ctx96-live-20260923.log) | `9fac29d962747babe95ac2e4507073a16675298c423a4e784561fcc6c6efa8a7` |
