# Contested premises: our own claims, attacked, and what survived

Kept rather than tidied away. Each entry names the claim, the artifact that attacked it, and
what the claim became. Entries are not deleted when resolved — a quiet retraction destroys the
audit trail that makes the rest of this repository worth arguing with.

Ordered newest first.

---

## 1 · "The slot number identifies the hook" — CONCEDED, and it was a memory-safety bug

**Claimed:** the trampoline could select a per-hook context builder from the slot a program
occupied. Encoded in `ls_slots.h` and the trampoline's dispatch for months.

**Killed by:** arming `mrhttp_setup_new_serverside` in slot 2 and reading the records
(2026-08-19). They came back as `fn:"rst_why_preserve_va"`, `file:""`, `line:26`,
`err:3266788480`. Exact counts, fictional fields.

**Why it was worse than wrong output:** `ls_ctx_rst_build` takes argument two as
`const char *file` and walks it for up to 256 bytes. Arming any function whose second argument
is not a readable pointer was a wild read on TMM's data path. `mrhttp`'s happened to be a valid
`struct uflow *`.

**What it became:** builders register themselves against the function name they serve
(`ls_ctx_reg.h`), resolved once at arm time. An unregistered function gets the raw registers and
no dereference. **Note the shape:** `ls_slots.h` was itself created to fix "bytes of the right
length and the wrong meaning" one level in. The same error recurred one level out, and its
`_Static_assert`s could not catch it because they proved the slots were *distinct*, not that a
slot's builder matched the function armed into it.

---

## 2 · "The build-id gate proves the artifacts are fresh" — CONCEDED

**Claimed:** comparing the index's build ID against the running binary establishes that the
artifacts describe what is deployed.

**Killed by:** a `make container` that exited 0 and packaged a binary byte-identical to the one
already running (2026-08-19). Every gate passed. **A stale DEB agrees with itself perfectly** —
same binary, same ID, index matches, image ships without the change.

**What it became:** agreement is not freshness. `bnk-check-deb-contains-substrate.sh` compares
the package against the *sources* — no substrate source may be newer than the DEB, and every
non-static substrate function must appear in the packaged debug symbols.

---

## 3 · "Freshness can be proved by comparing the packaged and linked build IDs" — PARTLY
OVERTURNED WITHIN THE SAME SESSION

**Claimed**, as the fix for #2: TMM's build ID is content-derived, so the DEB's binary and the
one `make` linked must match.

**Killed by:** measurement. `make container` runs `rpmbuild`, which recompiles from a source
tarball inside the toolchain container, so a **correct** package carries a different ID —
`aef8cac4` linked against `03c6f0e0` packaged, both containing the change. The check as first
written would have rejected every good package.

**What survived:** the underlying observation *was* right — the build ID **is** content-derived
(`74ed5caf` → `aef8cac4` across a substrate change), which had been doubted. The inference from
it was wrong. Freshness is now a timestamp comparison plus symbol presence.

---

## 4 · "The benchmark gives the per-call cost" — CONCEDED TWICE

**First:** the op wedged the loader thread, because it allocated on a thread where TMM's
allocator freezes. Fixed by routing it through the same handoff loads use.

**Then, still wrong:** it timed `ubpf_exec_ex` — the **interpreter** — while every armed hook
prefers `jit_fn`. The figure described an execution path nothing runs, pessimistic by roughly
4×. Killed by reading the function rather than trusting its output.

**What it became:** it compiles and times the JIT, and reports `path=jit` or `path=interp`
first in the reply. And the number itself is bounded — see #5.

---

## 5 · "≤ 11 ns is the program's execution cost" — SELF-ATTACKED, HELD AS A BOUND

**Killed by:** its own data. `demo_pass` does nothing but return; `rst_watch` builds a record and
emits it. `rst_watch` measured **faster**. That is impossible, and it means the `rdtsc` pair
doing the measuring costs about as much as the thing measured.

**What it became:** an upper bound rather than a value. The four smallest programs are
indistinguishable from one another. `generic_probe` (68 cycles) and `rate_gate` (272) clear the
floor and are real.

---

## 6 · "The vendored uBPF revision cannot be stated" — FALSIFIED

**Claimed** in `REPRODUCING.md` and `DOC-STATUS.md`: the vendored copy has no version-control
history, so its upstream revision is unrecoverable. Also claimed: the PREVAIL binary reports
`v0.2.6`.

**Killed by:** looking (2026-08-20). The vendored copies in this repo **do** carry git history:
uBPF is `c900ed9f` from `iovisor/ubpf`, PREVAIL is `06769f7b`, tag **`v0.2.5`** — and the binary
reports `v0.2.5`, not `v0.2.6`. The "cannot be stated" claim was true of a *different* copy, the
build box's git-less `~/code/tmm/.ubpf` extract, and had been generalised to the repo.

**What it became:** `substrate/check_vendor_pin.sh`, which compares the revisions and requires
the recorded patch to apply cleanly to the pinned commit — so "base plus this diff" is
reproducible rather than asserted.

---

## 7 · "Signals are the delivery path for hardware watchpoints, and that is the objection"
— FALSIFIED

**Claimed** in `hook-types-plan.md` §2.4, and it drove the risk rating: SIGTRAP arriving anywhere
in a run-to-completion poll loop.

**Killed by:** `prototype/watchpoint/wp_probe.c`. `perf_event_open` breakpoints sample into an
mmap'd ring that a *different* thread drains. The watched thread takes the trap and continues;
nothing runs in it. Verified on x86_64 and aarch64.

**What survived, and it is worse than the original objection:** the privilege ask.
`CAP_PERFMON` — the narrow capability intended for exactly this — is **refused** at
`perf_event_paranoid=4`. It takes `CAP_SYS_ADMIN` in a data-plane container, or a host sysctl
change. That may end the discussion regardless of the delivery mechanism.

---

## 8 · "No F5 source file is modified" — CONCEDED, and the phrasing was the problem

**Claimed** repeatedly across the repository.

**Killed by:** `git status` on the build tree. 46 files and ~7,800 lines added, three build
configuration files edited, one compiler flag.

**What survived:** no existing F5 *function body* is edited — startup registers through TMM's own
`INIT_FUNC` linker set. That is a real and much smaller claim, and it is the one now made.

---

## 9 · Claims retired but not individually documented here

`DOC-STATUS.md` §"claims the build falsified" carries the pre-build design claims that the
implementation retired — including *"there is deliberately no prototype; nothing in this repo
executes a shield."* That page is the older half of this record and is not being duplicated
into it.
