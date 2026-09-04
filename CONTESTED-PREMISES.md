# Contested premises: our own claims, attacked, and what survived

Kept rather than tidied away. Each entry names the claim, the artifact that attacked it, and
what the claim became. Entries are not deleted when resolved — a quiet retraction destroys the
audit trail that makes the rest of this repository worth arguing with.

Ordered newest first.

---

## 15 · "We pin every signature to a single build" — FALSIFIED, and the signature machinery is guarding fields nobody reads

**Claimed**, by me, on 2026-09-04, while arguing that embedded BTF and build-pinning are redundant:
*"we already pin every signature to a single build (`--build-min/--build-max 0x269b5d25`)"* — and the
whole argument for taking BTF out of the binary rested on it. If a program is valid for exactly one
build, its offsets can be baked and no runtime type information is needed.

**Killed by** reading the loader instead of remembering a command line. Three findings, each worse
than the last:

1. **The loader never checks the range.** `build_min`, `build_max` and `expires_with` live in the
   signed 112-byte binding. Outside `shield_abi.h`, they appear in exactly three files:
   `check_sig.c:154-157`, which asserts that flipping a bit in each **is detected by the signature**;
   `check_audit.c:99-102`, which sets them in a fixture; and `ls_audit.c:403-409`, which **logs** them.
   Nothing compares them to anything.
2. **The pipeline does not even set them.** `sign_shield.py` defaults `--build-min 0`,
   `--build-max 0xffffffff`, `--expires-with 0xffffffff`, and `bnk-build-programs.sh:196` passes none
   of the three. Every program the pipeline has signed is valid on **all builds, forever**.
3. **No build gate exists on-box at all.** `ls_audit_read_build_id()` reads the running build id from
   `/proc/self/exe`, `ls_audit_build_id()` returns it, and no caller compares it. The build-id
   agreement check that does exist runs at **image bake time** (`ls-verify-layer.sh:36-37`). That is a
   packaging gate: it proves the hook index matches the binary in the image, and says nothing about
   whether an arriving program was signed for it.

**Why this is the most expensive shape a gap can take.** Every visible signal says the field is
enforced. It is in the signed structure. A test proves tampering with it is caught. The audit record
prints it on every operation. A reviewer following any of those three trails concludes the range is a
control. **Signing a field is not checking it, and a test that a field is signed is not a test that it
is honoured** — `check_sig.c` proves the former and reads, at a glance, like the latter.

**What saved us, and it is luck plus one deliberate property.** Nothing stale has loaded, for two
reasons that are not the range: the hook index in the image is build-matched by the bake-time gate, so
name→address cannot drift; and CO-RE relocation resolves field offsets against the **running binary's
own** `.BTF`, which `ls_vm.c:594` describes exactly right — *"it IS the binary's own section"* — so
offsets are self-correcting by construction.

**Where it lands on the work it was raised for, which is the reason to write it down rather than fix
it quietly.** The BTF-out-of-band plan's phase 3 **deletes the self-correcting property**. Baked
offsets plus an unenforced build range is silently-wrong reads with nothing on-box able to notice —
the same failure family as the bitfield defect, which produced wrong values and passed every gate
without a complaint. So the sequencing is not a preference: **enforcement lands before the embedded
BTF is removed, or the change is a net regression.** The argument I used to justify the work turned
out to be the work.

---

## 14 · "The shipped image discloses symbols, and the entry pad discloses function boundaries" — BOTH FALSIFIED in one `readelf`

**The claims.** Two, made at different times, both about what the deployed ELF gives an attacker:

1. `engine-hard-problems.md` §4.1 and `env/scripts/bnk-strip-debug.sh`, since 2026-09-01: the image
   carries *"76 MB of symbols"* in `/usr/bin/tmm64.debug`, so removing that file removes a symbol
   disclosure.
2. Stated in session on 2026-09-03, when scoping what the pad costs: the entry pad is *"structurally
   visible … it reveals function boundaries even with no names"* — a small but real added disclosure,
   *"inherent to the technique."*

**The falsifier, pre-registerable in one line:** read the sections and the symbol table of the
**pristine F5 image**, not of our build. Never done — both claims came from a filename and from
reasoning about what a pad looks like.

**What the measurement says** (build box, `tmm-img:v10.207.3-HEAD.b13f8f034e`, unmodified by us):

```
tmm64.debug    76,019,416  ELF exec, stripped   symtab FUNC: 0   .debug_*: 0   .BTF: 0   FDEs: 117,852
tmm64.no_pgo   57,107,456  ELF exec, stripped   symtab FUNC: 0   .debug_*: 0   .BTF: 0   FDEs:  72,142
build ids       1f7b70d0…            269b5d25…
```

Claim 1 is **false in its premise.** `tmm64.debug` is not a debug companion and holds no debug
information: it is a **second stripped executable** from a different build configuration, 76 MB
against 57 MB because it is unoptimised. F5 ships **no symbols and no DWARF at all**. The file is
still worth deleting — 76 MB of duplicate, differently-compiled, **unpadded** copies of every
function is ROP surface and a diffing aid — but that is a different and smaller argument, and the
script now says so.

Claim 2 is **false in its conclusion, and in the more interesting direction.** `.eh_frame_hdr` in the
stripped shipped binary carries a **sorted, binary-searchable table of 72,142 function start
addresses** — unwind metadata the C runtime requires, generated by the compiler, present before we
touched the build and identical (72,142 in both) before and after the pad flag. Function boundaries
were never withheld; the pad adds nothing to a disclosure `readelf -S` already completes.

**What both share, and why this entry exists rather than a quiet edit.** Each was a confident
statement about an artifact that was **one command away** and never read — the exact shape CLAUDE.md
rule 5 exists to prevent, committed twice about the same file. The correction also *strengthens* the
position it was meant to weaken: with F5 shipping zero symbols and boundaries already public, the
**only** layout disclosure anywhere in the deployed image is the `.BTF` section **we add**.

---

## 13 · "The cluster was left healthy, all experiments reverted" — FALSIFIED, and it takes a
measurement's key word with it

**Claimed**, by me, repeatedly, as the closing line of the brainpool work: the experiments were
reverted and the cluster left clean. Stated again in this session while reasoning about what the
cluster could and could not reach.

**Killed by:** the owner asking, in passing, *"are there programmed iRules that can be interfering
with our system."* Enumerating `f5-big-cne-irules` — which I had never once listed — returned
**two live custom resources in `spk-app-1`, applied seven days earlier, by me**:

```tcl
when CLIENTSSL_HANDSHAKE {                       # ls-certext-irule
    log local0. "LSD5F before cert_constraint"
    SSL::cert_constraint "1.3.6.1.4.1.3375.99" [string repeat "A" 70000]
    log local0. "LSD5F after cert_constraint"
}
when HTTP_RESPONSE { HTTP::header insert X-LS-Irule fired }   # ls-probe-irule
```

Both were **firing**, not merely present: `X-LS-Irule: fired` came back on a live `.99` response,
and the TMM log held 102 `LSD5F` lines with the most recent at **2026-09-02 13:23:02** — during
this session. So every TLS handshake on this cluster for seven days carried a 70 KB
certificate-constraint injection and two syslog writes, of my own making.

**What it costs the measurement, stated precisely, because the loss is narrower than it first
looks.** `GROUND_TRUTH.md` records the brainpool precondition as reading non-zero stale data *"on
plain x25519 TLS 1.3 handshakes"* — **`matched 6 of 6`** — and quantifies it at **`>65000`**.

- **The A/B differential survives.** Vulnerable `6/6` vs patched `0/6` was taken with the *same*
  iRule active on both builds, one variable between them and equal `fired` counts. A confound
  present identically on both sides of a differential does not explain the difference. The
  reverse-patch did reintroduce the condition, and a probe can still tell the two builds apart.
- **The word "ordinary" does not survive.** The traffic was not ordinary; it was traffic I had
  been perturbing continuously and forgotten about. Any claim of the form *this is what happens on
  normal handshakes* is unsupported until re-taken.
- **The naive version of the confound is excluded, and saying so matters more than the
  accusation.** If the field were reading my injected bytes it would read `0x4141` = 16,705; the
  measurement was `>65000` ≈ `0xFFFF`. So the iRule was **not** the direct source of the value.
  What a 70 KB allocate-and-free per handshake plausibly *does* affect is **slab recycling** — and
  what recycled memory contains is precisely the quantity under measurement. That is enough to
  require a re-take and not enough to call the finding wrong.

**Why the claim could not have caught itself, which is the same shape as entry 11.** "Reverted"
meant *I deleted the artifacts I remembered creating* — images, armed slots, probes. It never
meant *I enumerated the cluster's configuration*. A revert that covers one class of state and not
its neighbour reads exactly like a revert. It converts "I have not looked" into "I checked."

**A second failure sat underneath it, and it is the more general one.** Asked whether a security
profile existed that would make a CVE reachable, I ran
`kubectl get crd | grep -iE "security|psm|waf|firewall"`, got nothing, and wrote down *"no
security CRD exists at all."* The resources are named **`SecPolicy`** and **`F5BigFwPolicy`** —
`sec`, not `security`; `fw`, not `firewall`. **The pattern could not have matched.** A wrong grep
returns zero hits, which is indistinguishable from a true negative and raises no error, so the
entire cost lands on whatever conclusion is built on top. That false negative was then used as
evidence to declare CVE-2025-36557 unreachable. Owner's rule, now standing: *"when you do greps,
dont assume you know the strings to be looking for."*

**What it became.** Both iRules deleted (backed up verbatim first, with their applied-config
annotations, so restore is exact), and the removal **verified by behaviour** rather than by the
delete's exit code: no `X-LS-Irule` on a fresh `.99` response, **0** `LSD5F` lines across five
fresh TLS handshakes, TMM `Running` with 0 restarts. The `GROUND_TRUTH.md` rows for the brainpool
precondition are flagged CONFOUNDED pending a re-take on the now-clean baseline. And the standing
correction to the revert procedure: **enumerate the cluster's config unfiltered before claiming a
clean baseline, and before any measurement whose meaning depends on the traffic being ordinary.**

**The finding hidden inside the mistake, which is worth more than the correction.** That iRule is
proof of a capability the repo had recorded only as a *contrast* ("not iRules", "iRules cannot
reach these"): arbitrary TCL, accepted through an ordinary custom resource, reached
`SSL::cert_constraint` with a 70,000-byte value and TMM logged both before and after it. That is a
**config-surface path into TMM internals that no CRD field exposes** — and it had been working for
seven days while I concluded from a CRD's field list that a CVE's precondition was unreachable.
See `GROUND_TRUTH.md`.

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

**Resolved in part, 2026-08-25 — the offsets were right, and are no longer typed.** The frozen
`#define`s were checked against TMM's own debug info: all seven correct, plus the struct sizes and
the version bit-shift. So the silent-wrong-offset risk had not materialised. It was also never
being managed: the banner read `GENERATED for build 1778975c` while the debug tree was `e35ed0ed`
and the cluster ran `499b8c30`. Three builds, one frozen set of literals, and nothing able to say
whether they still held.

They are now derived per build by `mk_ctx_parse.py` into a generated header, with **no fallback** —
absence is a compile error, because a fallback is how a wrong offset stays silent. Two independent
DWARF readers must agree on all 13 derived values; on TMM's real debuginfo they do. The
cross-check has already caught two of its own defects that a single reader would have shipped: a
`DW_AT_const_value : 1 byte block: 0` form that appears in real DWARF but not in a fixture, and a
bitfield whose byte the two readers reported differently until the comparison moved from the raw
`offsetof` primitive to the derived result. `ls_ctx_parse_sane` exists and executes. The
constraints this must live under are written down in `substrate/FIELD-CONTRACT.md`.

**Still open:** the measurement that started this — whether the ctx the *CVE* hook's builder
produces matches what the shield expects — remains unmade, because that hook has never fired.
Correct offsets are necessary and not sufficient.

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
