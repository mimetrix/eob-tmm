# Reproducing the live result

**The claim to reproduce:** a verified eBPF program is loaded over a socket into an
already-running TMM, armed at a function entry while traffic flows, and disarmed again — no
rebuild, no restart.

This file is the path from a clean checkout to that. It also states, plainly, the three places
where **this repo is not sufficient** and what you need besides it.

---

## What this repo can do on its own

```sh
make -C substrate check
```

22 checks on any Linux host with a C compiler, Python 3 and clang: the ABI header's wire-layout
assertions, the safe-return gate cases, the hook-map schema, the budget pass, PREVAIL's verdict on
each candidate shield in **both** directions, the VM-geometry finding, and compilation of the
actual in-TMM sources against the real uBPF API.

On x86-64 it additionally **runs** the mechanism's load-bearing proofs: `check_selfpatch` (a
process patching its own `r-xp` `.text` so execution sees it), `check_arm` (arming a live function
and reversing it), and `check_swap` (the naive swap racing under stress while `text_poke_bp` stays
clean). On aarch64 those skip loudly rather than silently passing.

**What it cannot do:** none of that is a data plane. It is bench harnesses.

---

## The three things this repo is not

**1. It is not the TMM source tree.** The `substrate/ls_*.c` sources are compiled into TMM
*elsewhere* — `gitswarm.f5net.com/tmm/tmm` (MBIP), built with `make tmm-gdb`. Everything that tree
needs is in [`substrate/TMM-TREE-DELTA.md`](substrate/TMM-TREE-DELTA.md): eight `filelist` entries,
23 whitelist symbols per variant, one compiler flag, and why `ls_prep.c` is the one file without
`STDINC`. **No F5 source file is modified** — that is checkable, and worth checking.

**2. It is not the cluster.** Reproducing the live arm needs a BNK build box and a datkube cluster.
[`env/bnk-dev-runbook.md`](env/bnk-dev-runbook.md) stands both up from nothing.

**3. It is not a signed pipeline.** Nothing verifies a signature (scope item 4), so the loader
accepts **unverified programs** whenever `LS_LOAD_SOCKET` is set. That is why the socket is
env-gated and off by default, and why none of this is near a production box.

---

## The path

| # | Step | With |
|---|---|---|
| 1 | Stand up the build box and datkube | `env/bnk-dev-runbook.md` §0–§11 |
| 2 | Apply the substrate to the TMM tree, build | `substrate/TMM-TREE-DELTA.md` |
| 3 | Verify the image is the padded production shape, roll it out | `env/scripts/bnk-ship-image.sh` |
| 4 | Get the hook's entry address from the **deb pair** | `env/scripts/bnk-entry-address.sh` |
| 5 | Confirm SIGTRAP is neither blocked nor already caught | `env/scripts/bnk-check-sigtrap.sh` |
| 6 | Stand up a traffic path (backend → **IPAMRange** → virtual server) | `env/scripts/bnk-traffic-path.sh` |
| 7 | Load a program, arm it, disarm it | `substrate/loader-client/ls_client.py` |
| 8 | Prove *distinct* bytecode is loaded and discriminated | `substrate/loader-client/check_load_distinct.py` |

**Tested 2026-08-14** against the build box and the live cluster — steps 4 and 5 run for real,
step 3's `verify` runs for real, and step 6's resources are validated server-side with
`--dry-run=server`. What was *not* re-run: step 3's `deploy` rollout and step 6's apply, because
both mutate a working cluster. Testing found six defects in scripts that had passed a syntax check,
including two wrong CRD enum spellings and a verdict that contradicted observed reality.

Steps 4, 5 and 6 each encode a fact that cost a day when it was missing:

- **Step 4** — packaging **re-links** the binary, so the build tree's address is not the pod's
  address. Arming the wrong address is silent, because nop pads exist at plenty of wrong places.
- **Step 5** — if any TMM thread *blocked* SIGTRAP, a mid-patch trap would kill the process and the
  whole approach would be dead. This is cheap to check and expensive to assume.
- **Step 6** — BNK allocates VIPs from an `IPAMRange` custom resource that the F5 examples never
  mention. Without one the service stays pending and every connection is refused, which looks
  exactly like a broken data plane. "Traffic has never reached the hook" sat open for a day because
  of it.

---

## What a successful run looks like

**Armed** — the five nops at the hook's entry become a call to the trampoline:

```
f3 0f 1e fa      endbr64
e8 f0 6c 75 ff   call   ls_trampoline_entry
```

Verify the call target resolves to `ls_trampoline_entry` exactly, not merely that the bytes
changed.

**On the request path** — with a hook armed on `http_parse_client_headers`, the fire count tracks
requests **1:1**. 16,000 requests gave `fired=16000`. Anything other than 1:1 means the hook is not
where you think it is.

**Under load** — 10 loads during 9,000 requests: 0 failures, latency percentiles unchanged.

**Disarmed** — the nops come back and the fire count stops advancing.

---

## What you will not be able to reproduce, and why

- **A CVE actually mitigated on live traffic.** The worked-example target is unreachable on BNK:
  `prot_transfer_log_profile` has no Kubernetes CRD field, so the check-then-reread window cannot be
  driven from outside. Every program armed live so far returns `FALLTHROUGH` by construction, which
  means the *mechanism* is demonstrated and the *mitigation* is not. See
  [`bnk-integration-map.md`](bnk-integration-map.md) §6.
- **A per-call cost number.** The counter mean is dominated by preemption artifacts, and the bench
  op that would give a clean minimum still runs on the loader thread and wedges it.
- **Anything on appliance or VE.** All of this is MBIP/BNK. Whether CBIP and MBIP share one source
  tree is **unverified** — and reading `#ifdef`s would not settle it, because at least one
  divergence we hit is about what gets *linked*, not compiled. See
  [`big-ip-live-shield-design.md`](big-ip-live-shield-design.md) §10.
