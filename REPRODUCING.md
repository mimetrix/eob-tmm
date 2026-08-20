# Reproducing the live result

> **Status: partially stale, and the specific gaps are listed here rather than left to be
> discovered.** This page was last tested 2026-08-14. Since then arming moved from a
> hand-typed hex address to a symbol name resolved through a baked-in index and gated on
> build ID; the tree sync, the image bake and the drain rebuild all became scripts; and two
> helpers, two tracepoints and a program-controlled egress path were added. The path below
> still describes the older workflow.
>
> **Three recording gaps would stop a reproducer even inside F5:**
>
> 1. **RESOLVED 2026-08-20 — the pin is recorded and enforced.** This item claimed the
>    vendored revision could not be stated. It could: the copies in this repo carry git
>    history. uBPF is `c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d` from `iovisor/ubpf`; PREVAIL
>    is `06769f7b508214e63b97905d275920f7e90182fa`, tag **`v0.2.5`**, and the binary reports
>    `v0.2.5` — the earlier `v0.2.6` claim was wrong. `substrate/check_vendor_pin.sh` compares
>    both revisions against the recorded pins on every `make -C substrate check`.
>
>    What *was* true is that the build box's `~/code/tmm/.ubpf` is a git-less extract, so its
>    provenance cannot be read from itself. That is a property of that copy, not of the pin,
>    and generalising it was the error. See `CONTESTED-PREMISES.md` #6.
> 2. **uBPF carries one patch, and the tree is deliberately unpatched.**
>    `substrate/ubpf-patches/0001-jit-scratch-rightsize.patch` is applied when the library TMM
>    links is built, not to the checkout — so the source tree and the linked artifact are not
>    the same thing, on purpose. The check requires the patch to apply cleanly to the pinned
>    revision, which is what makes "base plus this diff" reproducible rather than asserted.
>    PREVAIL is unmodified, and that is now checked rather than promised.
> 3. **The current workflow is undocumented here.** `bnk-sync-substrate.sh`,
>    `bnk-bake-tools.sh`, `bnk-preflight.sh`, arming by name and the build-ID gate are all
>    load-bearing now and appear nowhere below.
>
> None of the three is a technical barrier — each is something that was done and not written
> down. Fixing them is a bounded task and it has not been done.

**The claim to reproduce:** a verified eBPF program is loaded over a socket into an
already-running TMM, armed at a function entry while traffic flows, and disarmed again — no
rebuild, no restart.

This file is the path from a clean checkout to that. It also states, plainly, the three places
where **this repo is not sufficient** and what you need besides it.

---

## What this repo can do on its own

**Step one, and it is not optional:**

```sh
./bootstrap.sh
make -C substrate check
```

**Why there is a step one.** This section used to say the checks run "on any Linux host with a C
compiler, Python 3 and clang". Measured on a fresh clone on 2026-08-20, that was **false**: four
targets — `check-skeletons`, `check-vm`, `check-map`, `check-glue` — failed on `fatal error:
ubpf.h: No such file or directory`, three screens below forty passing lines. uBPF and PREVAIL are
vendored and **gitignored**, so they are present on every machine this work was done on and absent
from every machine it would be reproduced on, and nothing in the repository could notice because
everything that would notice was running where they existed. That is recorded here rather than
quietly fixed, because it was wrong in the one document whose whole job is reproduction.

`bootstrap.sh` clones both at the revisions [`substrate/vendor.pins`](substrate/vendor.pins) names
— **from source, from the upstream origins, never a prebuilt artifact** — verifies them with
`check_vendor_pin.sh`, and runs uBPF's cmake configure, because `ubpf_config.h` is *generated* and
four checks include it. `./bootstrap.sh --check` reports what is missing and changes nothing.
`make check` now begins with `check-prereqs`, which names the missing header and the one command
that fixes it instead of failing as a compiler error at the bottom of a long log.

Once bootstrapped: the ABI header's wire-layout assertions, the safe-return gate cases, the
hook-map schema, the budget pass, PREVAIL's verdict on each candidate shield in **both**
directions, the VM-geometry finding, the Ed25519 signature gate against freshly generated keys, the
audit trail's 21 assertions, and compilation of the actual in-TMM sources against the real uBPF
API.

### Measured, from nothing, on 2026-08-20

Clone into an empty directory, `./bootstrap.sh`, `make -C substrate check`:

```
bootstrap exit 0    uBPF c900ed9f cloned, configured, libubpf.a built; PREVAIL 06769f7b cloned
make check exit 0   59 ok, 0 failures, 3 loud skips
```

**Read the skips, because exit 0 is not "everything ran".** On that host:

| skipped | why | what you lose |
|---|---|---|
| `check_shields` | `ebpf-verifier/bin/prevail` not built — PREVAIL needs `libboost-dev` and `libyaml-cpp-dev`, and `bootstrap.sh` reports the failure and continues | **The verifier's verdict on every candidate program, in both directions.** This is the biggest one: a skipped verifier is not a passing verifier |
| `trampoline_x86_64.S`, `ls_arm.c`, `check_swap`, `check_selfpatch` | the host was **aarch64** | The load-bearing proofs — a process patching its own `r-xp` `.text`, arming a live function and reversing it, the naive swap racing under stress. They *run* only on x86-64 |

So a clean `make check` on aarch64 without PREVAIL is a weaker statement than the same command on
x86-64 with it, and the output says which one you got rather than printing the same summary either
way. If you want the full set: an x86-64 host, plus those two packages before `bootstrap.sh`.

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
`STDINC`. **No existing F5 function body is modified** — checkable, and worth checking. The tree
does gain 39 files and three edited build-configuration files; see `DOC-STATUS.md`.

**2. It is not the cluster.** Reproducing the live arm needs a BNK build box and a datkube cluster.
[`env/bnk-dev-runbook.md`](env/bnk-dev-runbook.md) stands both up from nothing.

**3. It is a signed pipeline, and that is not the same as a trusted one.** Programs are signed
after PREVAIL accepts them and verified inside TMM before admission (scope item 4, built
2026-08-20). What remains unsigned is the *request*: the loader socket does not authenticate its
peer, so anything that can reach it may ask. Every request IS now recorded --- one `ls_audit:`
line per operation, with the caller's pid, uid and gid as the kernel reported them --- but a pid
is not a person, and under `kubectl exec` it belongs to a process spawned by an API call TMM
cannot see. The socket stays
env-gated and off by default for that reason, and the signing key lives in a file on a developer's
workstation rather than in an HSM --- so none of this is near a production box.

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

- **A CVE actually mitigated on live traffic.** Every program armed live so far returns
  `FALLTHROUGH` by construction, so the *mechanism* is demonstrated and the *mitigation* is not.
  The worked-example target is **not reachable through BNK configuration**: the fault needs a PSM
  log record, that needs `alarm_mask != 0`, and every write to `alarm_mask` sits behind an
  `enforce->*` flag that no BNK CRD exposes. Demonstrating it therefore needs dev op `0x1005`, which
  sets those bits directly so ordinary traffic walks the real path. See
  [`bnk-integration-map.md`](bnk-integration-map.md) §6.
- **A per-call cost number.** The counter mean is dominated by preemption artifacts, and the bench
  op that would give a clean minimum still runs on the loader thread and wedges it.
- **Anything on appliance or VE.** All of this is MBIP/BNK. Whether CBIP and MBIP share one source
  tree is **unverified** — and reading `#ifdef`s would not settle it, because at least one
  divergence we hit is about what gets *linked*, not compiled. See
  [`big-ip-live-surface-design.md`](big-ip-live-surface-design.md) §10.
