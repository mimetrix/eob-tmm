# dtls_tx shield + the SAFE_RETURN evidence event — a live mechanism demo

**RECORD (2026-08-28).** What was built, deployed, and demonstrated on datkube, and the one thing
that blocked the `dtls_tx`-specific arm. Tiers per `CLAUDE.md`. The honest headline: **the
enforcement-evidence pipeline is proven live; the `dtls_tx` shield is verified but not yet armed
live, blocked on a relocator bug named below.**

## Why this exists

A reviewer asked the sharp question: *if a shield stops a real attack on live traffic, where is the
evidence?* A `safe_returns` counter that ticks up is not evidence — a SOC needs a pushed, timestamped
record of the event, with the context the shield saw. This is that mechanism, built and shown firing.

## The target — a real, live, non-CVE bug

`err_t dtls_tx(struct ssl_ctx *sc, enum ssl_rt rt, BYTE *p, SIZE sz)` (`ssl.c`). In the fragmentation
path, `frag[SSL_SZ_RDATA]` is an on-stack ~16 KB record buffer; per-fragment `fraglen` is clamped to
the message-left but **not** to the buffer, so a DTLS segment size `mss` (from `sc->cf->mss`, a
`UINT16`) larger than the buffer drives a copy past `frag[]` — a stack smash. Fix `401743ff1d`
(2026-08-27) adds the missing clamp. Our build (`df2e3a63` / `e2104734a9`, 2026-08-11) **predates**
it, so the bug is live for us; it carries **no CVE** (internal finding) — hence a *mechanism* demo,
not a public-CVE claim. Reachable: `dtls_tx` fired 80× under `openssl s_client -dtls1_2` (survey).

## What was built

- **Shield `dtls_txguard.bpf.c`** (+ a synthesized-threshold `dtls_txguard_demo`): reads
  `sc->cf->mss` and `sz` at entry — the fix's own precondition — and returns `SAFE_RETURN` (→
  `ERR_BUF`, the value `dtls_tx` itself returns on `fraglen<=0`). **PREVAIL-verified**, ~66 cycles.
- **Evidence event** — `tmm:shield:safe_return` (`LS_TP_HOOK_SHIELD`=10, schema 6, `struct
  ls_tp_shield_ev`, 56 B). Host-emitted in `ls_vm_call` on every `SAFE_RETURN`, enforce **and**
  monitor, rate-limited (first 8, then 1/64), through the existing `ls_tp_ring`→`ls_drain`→JSON
  pipeline. `ls_drain` renders it (`emit_shield`).
- **Per-slot safe value (item 7, v1)** — `ls_slot.safe_value`, set from `LS_SHIELD_SAFE_VALUE` at
  arm, delivered by `ls_tramp_dispatch` (previously hardcoded 0 — the `0==ERR_OK` footgun).

## The build/deploy chain (each gate that bit, so it doesn't bite twice)

1. Substrate edits → `bnk-stage.sh` → `bnk-sync-substrate.sh` (into the TMM tree; new header added to
   `substrate/.tree-expected-delta`).
2. `make tmm-gdb` → **globals-whitelist link failure** on the new `g_shield_ev_seen`; added to both
   `{default,debug}_whitelist_x86_64` (recorded in `TMM-TREE-DELTA.md`).
3. **`make tmm-gdb` alone ships stale code** — substrate files are untracked so `VERSION` never
   changes and `make container` repackages the old binary. `bnk-package.sh` clears the chain and
   verifies the DEB contains the new build (`a78c1dd0`, 40/40 substrate functions).
4. `bnk-bake-tools.sh` (rebuilds `ls_drain` from source, embeds BTF/hook-index/signatures) →
   `tmm:shieldev`. `bnk-ship-image.sh verify` → READY.
5. Ship per-node `ctr import` + `kubectl set image` + roll. **`tmm:ls` preserved** as rollback.

## What was demonstrated — MEASURED

Signature verification is armed (unsigned refused); shields signed on the build box with the key the
image trusts. A **monitor-only** demo shield (`evidence_demo.bpf.c`, unconditional `SAFE_RETURN` on
`http_parse_client_headers` — the hook that relocates cleanly and fires once per request) loaded and
armed live (`OK ARMED LIVE ... no restart`). Five `curl` requests:

- `armed=1 mode=1 fired=5 safe_returns=5 errors=0`; all requests **200** (monitor — body ran).
- Five `tmm:shield:safe_return` JSON records drained, one per request:
  `{"ts_ns":…,"seq":0,"slot":1,"hook":"shield","schema":6,"mode":"monitor","gen":1,"verdict":1,"ctx_len":40,…}`

So the **evidence-event pipeline is proven end to end on live traffic.** The demo shield trips
unconditionally — it proves the *pipeline*, not exploit detection.

## What is NOT yet done — and the blocker, named

The **`dtls_tx` shield itself has not been armed live.** Its load was refused: `CO-RE relocation
failed (rc=-5, LS_RELO_ENOFIELD)`. Both `ssl_ctx` and `connflow` are in the baked BTF, but `connflow`
has ~30 BTF entries and `ls_core_relo.c`'s `btf_find_struct` returns the **first** match — a
forward declaration with no members — so the pointer-chase read `sc->cf->mss` cannot resolve `mss`.

**Falsifier for the fix:** `btf_find_struct` must prefer a defined struct (VLEN>0 / non-zero size)
over a forward declaration when a name is ambiguous. When fixed, `dtls_txguard` loads, and the same
arm + a large-`mss` DTLS message shows the evidence event carrying the oversized `sz`. Until then the
`dtls_tx` shield is **MEASURED (verified) but SHIPPED-UNVALIDATED (not armed live).**

The built-in slot-0 shield separately fails `rc=-3` (zero-relocation refusal), so the
`LS_VM_SELFTEST` path is also dead until that robustness bug is fixed — a second, older instance of
the same relocator brittleness.
