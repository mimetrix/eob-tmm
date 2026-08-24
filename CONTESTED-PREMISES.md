# Contested premises: our own claims, attacked, and what survived

Kept rather than tidied away. Each entry names the claim, the artifact that attacked it, and
what the claim became. Entries are not deleted when resolved — a quiet retraction destroys the
audit trail that makes the rest of this repository worth arguing with.

Ordered newest first.

---

## 11 · "A `-dirty` stamp on the synced tree tells me what is deployed" — FALSIFIED the same
day it was added

**Claimed**, by me, in `bnk-sync-substrate.sh` on the morning of 2026-08-20: the staged copy is a
tar extract with no `.git`, "so packaging cannot work this out for itself" — therefore stamp the
commit, plus `-dirty` when the tree is not clean, and provenance is answered.

**Killed by:** the first signed load into the image built afterwards. It was refused. So was
every load after it. Nothing was wrong with the signature, the key, or the verifier: the image
carried an `ls-load.py` from before signatures existed, which sent no signature at all, and TMM
refused it correctly. The stamp said `-dirty` throughout and was true throughout.

**Why the stamp could not have caught it.** It was scoped to `substrate/` — the sources compiled
*into* TMM. The tools baked into the *image* come from `env/scripts/`, which no synchronisation
step touched and no stamp described. The two live in one repository and are copied to the build
box by different means, and I had checked the one I had just written a guard for.

**The general shape, which has now cost three cycles here in different costumes:** a gate that
covers one input and not its neighbour reads exactly like a gate that covers the input. It is
worse than no gate, because it converts "I have not checked" into "I checked." The earlier two
were the build-id gate that proved agreement and was read as freshness (entry 2), and the sync
check that compared the substrate and was read as comparing the tree.

**What it became:** `bnk-stage.sh`. One step refreshes `substrate/`, `env/scripts/` and
`env/docker/` together, from the **working tree** rather than `HEAD` — staging `HEAD` would
silently ship the previous version of the exact file under test. It verifies the far end by
hashing every staged file on both sides and comparing, because "the transfer exited 0" and
"the bytes match" are different claims. And it fails outright if the staged client cannot send a
signature, checked by capability (`grep read_signature`) rather than by a version string, since a
version is one more thing to keep in step.

**What is still not covered, stated rather than left to be discovered:** nothing verifies that
the *deployed* image's tools match the repo. `bnk-stage.sh` guards the input to the bake; a hand
edit inside a running container, or an image baked from a tree since changed, would still pass
everything here. The check that would close it is comparing hashes of the tools inside the
running pod against the repo, which does not exist yet.

---

## 10 · "OpenSSL can verify on the loader thread" — FALSIFIED, by the falsifier that
predicted it

**Claimed**, in a comment I wrote in `ls_vm_load.c` while adding signature verification: safe to
call `ls_sig_verify` on the loader thread, because "EVP allocates, and TMM's allocator freezes on
this thread. It is safe because ls_sig_verify calls into OpenSSL's own allocator, not TMM's ---
the loader thread is an ordinary pthread and libcrypto's malloc is glibc's."

**Killed by:** shipping it (2026-08-20). The first signed load never returned. `status` on that
pod timed out afterwards; the untouched second pod answered instantly. The proxy kept serving
throughout — this wedged the loader, not the data plane.

**The sharpest part of the evidence:** *no log line was produced at all.* The code prints either
`LOAD REFUSED` or `LOAD accepted --- signature verified` immediately after the verify call
returns. Neither appeared, which places the hang inside verification rather than anywhere after
it.

**Why the claim was wrong, and where the answer already was.** TMM overrides `malloc` globally,
so libcrypto's allocations go through `kern/malloc.c → init_thread_cache → spin_lock` on a lock
nothing ever `spin_init`'d. That is not a new discovery: it is written out in full **350 lines
above my change, in the same file**, as the reason `ubpf_create` is handed to a TMM thread —
ending "Measured, not inferred: the loader goes on-CPU and never returns." I read that file to
add the call and reasoned past its own explanation.

**What it became:** verification moved behind `ls_prep`, the handoff that exists for exactly this
class of call. The security property is unchanged — nothing loads until the signature checks out
— and the check now happens on the thread where allocation is legal. The binding and signature
are *copied* into the request on the loader thread, because the wire buffer is reused and the TMM
thread reads them later.

**Why this one is worth keeping rather than quietly fixing.** F6e was registered in
`02-RESEARCH-PARAMETERS.md` *before the work began*, in these words: "verification cannot run
where the load runs … if that turns out impossible, the design is wrong rather than merely
awkward." It is the only reason this was tested on a live TMM at all rather than reasoned about
and shipped. Pre-registration earned its keep here in a single instance.

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

## 12 · "The shield's context is validated on live traffic" — MOSTLY FALSIFIED, and the
advertised safeguard does not exist

**The premise, as it was being relied on (2026-08-24).** Asked whether the demonstrated mitigation
would have stopped a real CVE, the honest gap is the *context builder*: the self-test hands the
shield a struct it synthesised, while in production a builder in the trampoline reads the same
fields out of live registers and memory. The shield's logic being right says nothing about the
builder being right. So: is any builder validated against live traffic?

**What the falsifier was.** Drive traffic whose parse outcome is known in advance, arm a program
whose disposition depends on a context field, and require the counters to move as predicted. A
field read from the wrong offset produces a value uncorrelated with the input.

**Measured, on the working Gateway path:**

| input | predicted | measured |
|---|---|---|
| 20 well-formed requests | `fired +20`, `safe_returns +0` | `fired +20`, `safe_returns +0` ✓ |
| 10 × bad method `G@T` | `safe_returns` tracks `fired` | `fired +10`, **`safe_returns +0`** ✗ |
| 10 × control char in path | `safe_returns` tracks `fired` | `fired +10`, **`safe_returns +0`** ✗ |
| 10 × bad scheme | `safe_returns` tracks `fired` | `fired +10`, **`safe_returns +0`** ✗ |
| 10 × well-formed, same raw path | `safe_returns +0` | `fired +10`, `safe_returns +0` |

`fired` is exact and 1:1 with requests in every row — so **the trampoline fires on the real path,
once per real invocation, and that half of the delivery chain is validated.** But the malformed rows
are indistinguishable from the well-formed ones: the discriminating counter never moves.

**Three findings, none of which were visible from reading the code once:**

1. **`parse_watch.bpf.c` tests a field this repository already knew was dead.** Its predicate is
   `invalid_flags != 0`. The header of `http_hdrs_watch.bpf.c` records, as a defect it had already
   fixed in itself, that `invalid_flags` is *"HTTP/2+3 pseudo-header validity; never written on the
   1.x path, so it read uninitialised memory. It produced the RIGHT COUNT for the wrong reason."*
   We drive HTTP/1.1. So `parse_watch`'s disposition carries no information on this traffic, and
   the measurement above cannot separate "the offsets are wrong" from "the field is never written."
   The lesson that fixed one program was not swept into the other — see the standing rule about
   sweeping by claim rather than by file.

2. **The safeguard `ls_ctx_parse.h` advertises does not exist.** That header states the cost of its
   byte offsets plainly — *"here it is silent if wrong, so the program checks a value it can predict
   (see `ls_ctx_parse_sane`)"*. There is no `ls_ctx_parse_sane`. The only occurrence of that
   identifier in the repository is the comment claiming it. The one design that would have caught a
   wrong offset was described and never written, and the description reads as though it had been.

3. **The program that *does* carry a pre-registered prediction table cannot be armed here.**
   `http_hdrs_watch.bpf.c` uses `parse_err` (correctly) and ships three predicted counter movements.
   Its hook is `tmm_l7_http_headers`, a USDT tracepoint that is **not in this build's index**, so it
   is unarmable. Arming it at `http_parse_client_headers` instead — which is what happened earlier
   the same day — hands it a context it was not written for. `fired` still counts correctly, because
   `fired` is incremented by the host and is independent of the context; every field is not.

**What survives, and it is not nothing.** One builder *is* validated on live traffic: `rst_why`.
Ten records captured today read `file="tcp.c"`, `line=4689`, `cause="TCP RST from remote system"` —
a mutually consistent triple matching a call site documented independently in `rst-why-feed.md`
(`RST_WHY_CF(cf, "TCP RST from remote system")` at `tcp.c:4689`, the top-ranked site in an earlier
live sample). A builder reading the wrong argument register yields a mismatched or garbage triple,
which is exactly how the defect in premise 1 above was found. So the mechanism *can* deliver a
correct context from live registers, and has been shown to.

**Where this leaves the CVE claim.** `the shield stops this crash` stands. `it would have mitigated
the CVE` requires the builder for **that** hook to be right, and that hook has never fired
(`fired +0` across 30 requests, because it needs a security log profile with `${profile_name}` and
no CRD creates one). So the claim is *supported by the mechanism working elsewhere* and *unproven
for this target* — which is a weaker statement than the demonstration invites, and the reason to
keep saying it.

## 9 · Claims retired but not individually documented here

`DOC-STATUS.md` §"claims the build falsified" carries the pre-build design claims that the
implementation retired — including *"there is deliberately no prototype; nothing in this repo
executes a shield."* That page is the older half of this record and is not being duplicated
into it.
