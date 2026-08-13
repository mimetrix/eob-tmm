# The live patch — from CVE to shielded, step by step

### How a published CVE becomes a running shield on a live TMM data plane **without a rebuild and without a restart**: the full pipeline, each step tagged by where it runs and what it needs, grounded in what is built today.

The mission is **CVE shielding**. The mechanism is an embedded userspace-eBPF virtual machine (uBPF)
with an offline verifier (PREVAIL), reaching an *unmodified* function through **patched-entry
hooking** — the compiler leaves a 5-byte gap at every function entry, and arming rewrites that gap
into a call to a small trampoline that runs a verified program and acts on its verdict.

Two outcomes the program can select, applied by the host:
- **`FALLTHROUGH`** — run the original function body (nothing changed for the caller).
- **`SAFE_RETURN`** — skip the body, return a declared safe value (the crash never happens).

---

## Status legend

| Tag | Meaning |
|---|---|
| **[reuse]** | reused open source as-is — uBPF (`508d5e4b`), PREVAIL (`v0.2.6`), clang |
| **[built]** | built and proven (bench and/or pod) this program of work |
| **[dev-stub]** | present but simplified in the dev environment; production needs the fuller form |
| **[not-yet]** | remaining work, scoped but not built |

Each step also names **where it runs**: *admission-time* (off the data path, once per shield, on the
build/sign side) or *runtime* (in the pod, in TMM's address space).

---

## Phase 1 · Triage — is this CVE shieldable, and how? *(admission-time, human + tooling)*

1. **Read the advisory.** Pin the vulnerable function, the trigger condition, and the crash class.
   *Example:* `http_psm_profile_name_lookup` dereferences `prot_transfer_log_profile->name` with no
   null check (`http_psm.c:806`) → null-pointer dereference → TMM crash. **[built: analysis]**
2. **Confirm it is hookable.** Three gates:
   - *Padded?* The function must be in a build compiled with `-fpatchable-function-entry` (the TMM
     core — 56.3% of entries in our `no_pgo` build carry the pad). **[built]**
   - *Trivial return?* The safe-return path delivers a value in `rax`; a struct-by-hidden-pointer or
     FP return needs its own path (restricted in v1). **[built: the gate; policy table dev-stub]**
   - *Affordable?* The function's call rate (`path_class`) must tolerate a per-call VM check. **[built]**
3. **Decide the safe behavior.** Usually `SAFE_RETURN` with a declared safe value; sometimes a
   corrected in-program path. *Example:* restore the missing null check — return the safe value when
   `name` is null, else `FALLTHROUGH`. **[built]**

## Phase 2 · Author the shield *(admission-time, off-box)*

4. **Generate the `ctx`** for the function from the build's **DWARF** — the exact argument layout the
   program will see. The verifier models against this; it is never read from the running binary.
   **[reuse: DWARF; built: the pipeline]**
5. **Write the shield** (eBPF C): read `ctx`, test the condition, return `FALLTHROUGH` / `SAFE_RETURN`.
   Small — a few lines for a null-check restoration. **[built]**
6. **Compile** to eBPF bytecode: `clang -O2 -target bpf`. **[reuse]**
7. **Verify with PREVAIL** — memory-safe, bounded/terminating, stays within `ctx`; **reject** if not.
   Termination and memory are independent gates; both must fire. **[reuse: PREVAIL v0.2.6]**
8. **Budget pass** — worst-case cycle estimate (control-flow longest path over the *verified* bytecode)
   vs. the hook's rate-class budget; **reject** if too costly for that path. Note: *verified ⇒
   terminates*, which is **not** the same as a bounded worst-case execution time — the budget pass is
   what bounds cost, not the verifier. **[built: `substrate/budget_pass.py`]**
9. **Resolve the target + build the binding.** From the shipped build's **hook map** (one entry
   address per function, generated at build time from DWARF), take the function's entry address; add
   `prog_sha256`, the valid `build_min..build_max` range, `mode_ceiling`, and `expires_with`.
   *Example, from our real `no_pgo` build:* `http_psm_profile_name_lookup → 0xcd4700` (entry `endbr64`),
   arm site `0xcd4704` (the 5 nops). The binary is **non-PIE (`ET_EXEC`)**, so that address is also the
   runtime address — no relocation math. **[built: hook map for this function; generator dev-stub]**
10. **Sign** the binding + bytecode with F5's key. The runtime accepts only signed programs.
    **[not-yet — the dev loader accepts unsigned; scope item 4]**

## Phase 3 · Ship & load *(runtime, in the pod — no rebuild, no restart)*

11. **Distribute** the signed shield object to the fleet; the appliance pulls it. **[not-yet]**
12. **The loader receives it** over the load path, **checks the signature** against the baked-in key,
    **checks the binding matches this build-id**, and **refuses on any mismatch** (fail closed at
    admission). **[built: load path `substrate/ls_vm_load.c`; signature check dev-stub]**
13. **Load into a VM slot** (`ubpf_load_elf`, optional JIT) and resolve the entry address from the hook
    map. Per-call cost measured on the bench: **~10 ns JIT / ~48 ns interpreter**. **[built + proven]**

## Phase 4 · Arm *(runtime, live, traffic flowing)*

14. **Safe-swap the trampoline call** onto the padded entry using the kernel's live-patch protocol —
    `text_poke_bp`: write `INT3` over byte 0, `membarrier(SYNC_CORE)`, write the 4 displacement bytes,
    barrier, write the real `call` opcode over the `INT3`, barrier; a `SIGTRAP` handler covers any core
    caught mid-patch. This is coordinated across TMM's per-core threads so **no core ever executes a
    torn or stale instruction**. Bench result: clean across billions of calls, real private `.text`,
    under multi-core load. **[built + bench-proven; wiring into TMM's own threads = the current step]**
15. **Start in `MONITOR`** — evaluate and count, apply nothing. Watch the fire-count and `ctx` samples
    to confirm the shield sees the real condition and is not false-positiving. A `MONITOR` hit is
    distinguishable from a miss (the program always selects; the host decides whether to apply).
    **[built: modes + counters + ctx sample ring]**
16. **Promote to `ENFORCE`** (up to the binding's `mode_ceiling`). Now `SAFE_RETURN` actually skips the
    body. **The CVE is shielded.** **[built]**

## Phase 5 · Operate & retire

17. **Observe** fire count, safe-returns, per-call cycles (WCET tail), and exec errors; a canary can
    **auto-unload** on misbehavior. **[built: counters; auto-unload not-yet]**
18. **Retire** when the permanent patched TMM ships: **disarm** (safe-swap the pad back to nops),
    **revoke**, or let the binding **expire with the build-id**. Reclaiming a swapped-out program once
    no core is inside it (`item 0c`) is a separate concern. **[disarm proven; revoke/expiry partial]**

---

## Where this stands on BNK / datkube today

- **Build side is done and verified.** A `no_pgo` **stripped-release-shaped** TMM built with the pad
  and the VM linked in: **2041 TUs compiled with `-fpatchable`**, **36,522 / 64,897 entries padded
  (56.3%)**, `ls_vm` present, `rc=0`. The unstripped copy is the DWARF source for the hook map; the
  stripped copy ships in the pod.
- **The real target is armable.** `http_psm_profile_name_lookup @ 0xcd4700` carries `endbr64` + 5 nops
  at its entry — byte-for-byte the shape the bench harnesses armed — in a non-PIE binary, so its
  address is fixed.
- **The environment permits it.** The pod's TMM text is **4 KB pages (no huge pages)**, the node has
  **no kernel lockdown and no SELinux**, and self-patching needs no ptrace. The two environmental
  risks are retired.
- **Proven on the bench, not yet in the pod:** the trampoline, arming, the safe swap (incl. on real
  private `.text` under multi-core load), and the whole slice joined (VM verdict drives an armed real
  function). The remaining work is deploying the padded image and wiring steps 13–16 into the running
  pod so an arm lands on `http_psm_profile_name_lookup` under live traffic.

## The two honest gaps to a real production live-patch

Everything above is built, bench-proven, reused, or the wiring now in progress — **except two things**,
and they are the difference between this dev demo and a shippable capability:

1. **Signing (step 10) + in-TMM signature verification (step 12).** Today the loader accepts unsigned
   programs; production must reject anything not signed by F5's key. This is the trust perimeter and
   feeds the formal **TMA** (Threat Model Analysis), a gating prerequisite.
2. **Fleet distribution (step 11).** Getting the signed object to appliances is out of this repo's
   scope but on the critical path to "ship a shield, no window."

Neither is invention; both are named, scoped work.

---

## Canonical sources

- Outcome set, the host owns it — [`embedded-ebpf-substrate.md`](embedded-ebpf-substrate.md) §2
- What must be true for a hook to reach a CVE — [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) §10.1
- Loader ABI + wire layout — [`substrate/shield_abi.h`](substrate/shield_abi.h)
- Hook-map schema — [`substrate/hook_map.schema.json`](substrate/hook_map.schema.json)
- The safe swap, and why testing alone is weak evidence — [`safe-swap-plan.md`](safe-swap-plan.md)
- The bench-to-pod integration map — [`bnk-integration-map.md`](bnk-integration-map.md)
- A CVE end to end, line by line — [`explainers/cve-shield-walkthrough.html`](explainers/cve-shield-walkthrough.html)
