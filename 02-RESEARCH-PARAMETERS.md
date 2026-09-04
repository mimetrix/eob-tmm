# Research parameters, pre-registered with their falsifiers

**Falsifier-first.** A claim without a stated way to kill it is not a claim yet. Each open
question below carries, in advance, what result would retire it — so the answer cannot be
reinterpreted after the fact to fit whatever was found.

Registered 2026-08-20. Anything answered moves to `GROUND_TRUTH.md` with a tier; anything killed
moves to `CONTESTED-PREMISES.md` with the artifact that killed it.

---

## Open

### P1 · Can a hook be armed on a function outside TMM core?

**Claim under test:** displacement (copying leading bytes and writing a `jmp`) reaches the
~30,000 unpadded entries, OpenSSL included.

**Falsified if:** the offline relocatability analysis proves safe for a candidate, displacement
is implemented, and the function still cannot be armed without a fault; **or** the population of
safely-relocatable functions among those 30,009 turns out to be a small minority, which would
make the reach argument for displacement collapse.

**Status:** unbuilt. The index already classifies relocatability offline, so the second failure
mode is checkable *before* any code is written, and should be checked first.

### P2 · What does an armed hook cost on the data path?

**Claim under test:** the ≤ 11 ns execution floor is within a small multiple of the real
per-invocation cost under traffic.

**Falsified if:** instructions-retired via the PMU, or any independent method, puts the
per-invocation cost of an armed hook at more than roughly 5× the floor. That would mean the
trampoline and cache effects dominate and the floor is not a useful proxy.

**Blocked by:** `perf_event_paranoid=4`, and the watchpoint prototype established that
`CAP_PERFMON` does not lift it — so this needs the same privilege conversation as P4.

### P3 · Is `CAP_SYS_ADMIN` in a data-plane container acceptable?

**Claim under test:** watchpoints are a viable route to unpadded code.

**Falsified if:** security review rejects `CAP_SYS_ADMIN` for the TMM pod and the node sysctl is
not ours to change. Then watchpoints are dead regardless of their measured behaviour, and the
CVE story is permanently limited to TMM's own code.

**Not a measurement.** This is the one parameter no experiment can settle, and it gates P4.

### P4 · Does a watchpoint survive TMM's poll loop?

**Claim under test:** a 501 ns – 4.8 µs trap is tolerable on a path that fires rarely.

**Falsified if:** the trap in a run-to-completion poll loop causes dropped packets, a watchdog
trip, or measurable latency at the percentiles TMM is judged on — even at low hit rates.

**Precondition:** P3 answered yes. Testing it otherwise spends effort on a mechanism that cannot
ship.

### P5 · Does a generated probe report fields a consumer can decode?

**Claim under test:** `mk_probe.py` output is usable by something other than the person who
generated it.

**Falsified if:** decoding requires the generated `.bpf.c` to be shipped alongside every record
stream, which is the current situation — the host validates only the length and prints bytes.

**Status:** currently **failing**. Recorded as a limitation rather than a plan.

### P7 · Can the loader say who armed what, when, and on which binary — and can that record be trusted?

**Registered on 2026-08-20, AFTER the code was written, which is the wrong order and is recorded
as such.** Rule 3 of this repository says a claim with no stated falsifier is not a claim yet. The
falsifiers below were written as the assertions of `substrate/check_audit.c` while building it, so
the *substance* of falsifier-first held — but the register was updated afterwards, and the whole
point of pre-registration is that it cannot be tuned to what the code turned out to do. Treat
this entry as weaker evidence than P6's for that reason.

**Claim to be tested:** every control-plane operation on the loader socket leaves one durable
record naming the operation, its target, the kernel's view of the process that asked, the binary
it ran against, and the verdict the caller received.

**Falsified if any of these:**

- **F7a** — an operation happens with no record. Any hole makes the trail unusable as evidence,
  and the paths most likely to leak are the *early returns*: a message too short or too large to
  interpret. Malformed traffic must not be the one thing that leaves no trace.
- **F7b** — the record disagrees with what the caller was told. A trail that says OK where the
  reply said ERR is worse than no trail, because it will be believed. This is why the verdict
  field is the reply *verbatim* rather than a second computation from the same inputs.
- **F7c** — a caller can forge a record. A hook name is attacker-controlled text landing in a
  structured line, so a newline in it must not produce a second record and a quote must not end a
  field. Log injection is the oldest attack on an audit trail.
- **F7d** — a record is silently truncated. A shortened verdict changes meaning ("refused because
  X" versus "refused") while still looking complete, so any cut must be marked in the record.
- **F7e** — the "who" is self-reported. If the identity comes from the message rather than from
  the kernel, an attacker writes their own attribution. `SO_PEERCRED` is the only field here the
  peer cannot choose, and the test asserts the recorded pid against one it already knows.
- **F7f** — the binary named is not the one running. The record must carry the same GNU build ID
  the arming gate compares, not a compile timestamp, or the record and the refusal are describing
  different questions.
- **F7g** — recording an operation breaks the loader. The audit path runs on the loader thread,
  where `malloc` spins forever (`CONTESTED-PREMISES.md` #10). If a record cannot be emitted
  without allocating, this design is wrong rather than merely awkward — the same falsifier that
  fired on signature verification, registered again because the same thread is involved.

**What is NOT claimed, and is not a falsifier because it is a known limit rather than an open
question:** tamper evidence. A sequence number makes a deleted record visible as a gap and does
nothing about a rewritten one, and a hash chain would not help either, since anything able to
rewrite the log can recompute it. Durability here comes from the *sink* — stderr, which in this
deployment is the container log stream collected off-box by something TMM cannot write to. The
optional `LS_AUDIT_PATH` file sink is weaker on purpose and is for tests.

**Also not claimed:** that the record identifies a *person*. `peer_pid` names a process, and in a
`kubectl exec` that process is spawned by an API call this code cannot see. Closing that needs the
request to carry a signed operator identity, which needs the wire format to grow a field.

**Will not claim MEASURED until:** every F7 case has a test that fails before the fix and passes
after, and F7g is demonstrated on a live TMM rather than argued — the loader must still answer
immediately after emitting a record.

**P7 CLOSED, 2026-08-20 — 11 of 11 live on build `1c913003`, 21 of 21 off-TMM.** F7g is shown
rather than argued: 10 of 10 round trips answered after records were emitted, on the thread whose
allocator wedged signature verification two days earlier. F7a holds including the path most likely
to leak — a malformed 3-byte request is recorded as `op=MALFORMED`. F7b, F7c and F7d were each
caught failing first: the verdict was a paraphrase rather than a quotation, truncation was silent,
and my first fix for the truncation checked the wrong buffer.

**Two findings the pre-registered falsifiers did not cover, which is the interesting part.**
Neither was on the list, and both came from *reading the first real records* rather than from any
assertion:

- **ARM and DISARM recorded as `op_4099` and `op_4100`.** The trail exists to answer "who armed
  what" and the one record a reader would go looking for did not name itself. The off-TMM test had
  built its messages from the four ops in `enum shield_op` — which is exactly the set that was
  already named, so the test could not have found this. A falsifier list drawn from the interface
  you are testing inherits that interface's blind spots.
- **An ARM record carries an address, not a symbol.** `hook=0x1451204`. Name resolution happens in
  the client, where the per-build index lives, so TMM never sees the string the operator typed.
  Recorded as FALSIFIED in `GROUND_TRUTH.md` rather than fixed here: it is a wire-format change.

**And the ordering caveat at the top of this entry earned itself.** The falsifiers were written
alongside the code, and the two things they missed are both things the code's own shape made
invisible. Pre-registration before implementation would not have guaranteed catching them — but
registering afterwards guaranteed the list matched the implementation, which is the failure mode
rule 3 exists to prevent.

---

### P6 · Can a program be refused unless it carries a valid signature?

**Registered before the work, 2026-08-20.** The gap this closed was the largest one on
`GROUND_TRUTH.md`: the loader accepted anything and printed `unverified=yes` on every load. Both
verbs are past tense as of the same day --- see the closure note below.

**Claim to be tested:** an Ed25519 signature over the 112-byte `struct shield_binding`, verified
in TMM against a baked-in public key, refuses every program that is not signed by the holder of
the private key — while still admitting the ones that are.

**Falsified if any of these:**

- **F6a** — a program with a corrupted signature, a corrupted body, a signature from a different
  key, or no signature at all is *admitted*. One admission and the mechanism is worthless.
- **F6b** — a validly signed program is *refused*. A gate that blocks legitimate work gets
  disabled, which is worse than not having it.
- **F6c** — a signature valid for one program can be replayed onto a different program. The
  binding commits to the body via `prog_sha256`, so this fails if that hash is not also checked.
- **F6d** — a signature valid at one hook can be moved to another hook, or past its build range,
  mode ceiling or expiry. Those fields are inside the signed binding precisely so they cannot be.
- **F6e** — verification cannot run where the load runs. TMM's allocator freezes on the loader
  thread, so if OpenSSL allocates during verify it must happen on the handoff thread; if that
  turns out impossible, the design is wrong rather than merely awkward.

**A deliberate deviation from the ABI comment, recorded rather than silently taken.**
`shield_abi.h` says the signature is "over op, epoch, mode, prog_len, binding, prog". This work
signs **the binding only**, and lets the binding commit to the body by hash. Reason: `epoch` is
reused by the current implementation to carry the *slot number*, so signing it would bind a
signed program to one slot for no security benefit. `mode` is likewise bounded by the signed
`mode_ceiling`, which is the field that exists for it. If that reasoning is wrong the ABI
comment is right and this must change — which is why it is written down here.

**Will not claim MEASURED until:** every F6 case above has a test that fails before the fix and
passes after.

**P6 CLOSED, 2026-08-20 — all five falsifiers survived on a live TMM (build `bf7f7002`),
and re-verified on `92454510` by `env/scripts/bnk-test-signatures.sh`, 16 of 16.** That suite
exists because the first run of these tests was typed inline, and one of the checks is on a
*string* — a string check typed from memory checks the memory, not the string.
F6a: tampered body and tampered signature each refused, with *different* messages. F6b: a signed
program loads, arms, and fires (`fired=26`/`15`). F6c: the body hash is checked, so a signature
cannot be replayed. F6d: hook, build range, ceiling and expiry are inside the signed bytes.
F6e: verification runs behind the prepare handoff and the loader answers immediately afterwards.
Plus the debug toggle admits a bad program and shouts about it, and refuses again when reverted.

Two things went wrong on the way that were **not** cryptographic, and both were mine: the image
carried a client with no signature support (stale staging), and the signer hardcoded a context
ABI version of 1 against a build that declares 3. Neither would have been found by an off-TMM
test, and both produced refusals that were *correct* while looking like crypto failures.

**F6e FIRED, 2026-08-20.** Verification on the loader thread wedged it — TMM overrides `malloc`
globally, so OpenSSL's allocations hit the same allocator freeze the prepare handoff was built to
avoid. No log line was produced, placing the hang inside verify. Fixed by moving verification
behind `ls_prep`; see `CONTESTED-PREMISES.md` #10. **F6a–F6d remain proven off-TMM; the live path
is unproven again until the next ship.**

### P8 · Can a function EXIT (`fexit`) hook be installed without desyncing on a non-local exit?

**The design (ROADMAP, `co-re-plan.md`).** Exit hooks are done by hijacking the return address from
the entry trampoline — overwrite the caller-return on the stack with an exit stub, save the real one
(and the entry args) on a per-core LIFO shadow stack, run the VM with the return value at the stub.
This is the single extension that turns "read state before a function runs" into "measure/act on its
result", and answers the `fentry`-timing limit (fields `0` at entry).

**Falsified if:** any hookable function sits under a `setjmp`/`longjmp` (or C++ unwind) on a live
TMM path — a non-local exit skips the body's `ret`, so the shadow frame is never popped and the next
exit returns to the wrong address. If that is reachable in TMM's data path, the return-hijack design
is **wrong rather than awkward**, and exit hooks need a different mechanism (e.g. bounded per-target
opt-out, or intercepting the unwind). Secondary killers: tail-call `jmp` (no `ret` through the stub)
reachable on a hooked target, or shadow-stack depth unbounded by any real call graph.

**How to settle it before building:** survey TMM's debuginfo for `longjmp`/`_setjmp`/`siglongjmp`
call sites and their dominators; if none dominate a candidate hook target, the gate is clear for
that target set. Toolchain-/build-sensitive — run on the build box against the pinned binary
(rule 5), not from memory.

**SURVEYED 2026-08-26 on the build box (`eob-bnk-build-01`) — falsifier SURVIVED, gate CLEAR.**
`readelf` over two pinned binaries: the shipped debug companion `tmm64.no_pgo.debug` (build
`80aff243`, from `tmm-debuginfo_10.207-3.HEAD.b13f8f034e`) and the runtime `tmm.no_pgo` (build
`ef2496ca`). The runtime binary **dynamically links glibc**, so any `longjmp` call in TMM (or in code
statically compiled into it) would appear as an undefined import — and there are **none**:
`longjmp`/`setjmp`/`siglongjmp`/`_setjmp` are absent from `.dynsym`, `.symtab`, and DWARF. The C++
residual is closed the same way: **zero** `_Unwind_RaiseException` / `_Unwind_ForcedUnwind` /
`_Unwind_Resume` / `__cxa_throw` / `__cxa_begin_catch` imports — TMM's own code can neither *initiate*
an unwind nor *catch* one, so no hooked TMM frame can sit on a throw→catch chain. (`.eh_frame` /
`.gcc_except_table` are present but are passive CFI/backtrace metadata — `-fasynchronous-unwind-tables`
is default — not active propagation, confirmed by the total absence of any unwind-initiating import.)
Both candidate hook targets are present (`http_parse_client_headers @ 0xccc600`,
`ssl_alpn_match @ 0x101f940`). **Verdict:** the return-address-hijack + shadow-stack design is sound
for the data-path targets; the residual guard is per-target — a future hook placed on a frame that a
NEEDED C++ library could unwind through would need re-checking, but no such throw/catch chain exists
in TMM code today. MEASURED, tool-witnessed (`readelf`). **How the residual is covered (design):** a `longjmp` is handled for
free by keying the shadow stack to the stack pointer and reclaiming skipped frames (`kretprobes`
precedent); a C++ exception is handled by **refusing exit hooks on unwind-traversable targets** at arm
time (offline reachability), since overwriting a return address that the unwinder walks would corrupt
the unwind itself. Both fold into the fexit build, not a new open question.

### P9 · Can baked-at-sign-time field offsets be admitted safely once the binary's own BTF is gone?

**Why this is open now.** Taking the 6.4 MB `.BTF` out of the shipped binary
([`engine-hard-problems.md`](engine-hard-problems.md) §4.1) means resolving field offsets on the build
box and shipping bytecode with the offsets baked in. That deletes the property that currently makes a
stale offset structurally impossible: relocation today runs against the **running binary's own**
`.BTF` (`ls_vm.c:594`). Baked offsets plus an unenforced build range is silently-wrong reads with
nothing on-box able to notice — see [`CONTESTED-PREMISES.md`](CONTESTED-PREMISES.md) §15.

**Claim under test:** a signed digest committing the program to one build's layout is sufficient
admission control to replace on-box relocation.

**Falsified if** any of these holds after the change:

- a program signed against build A **loads** on build B (the digest gate is absent or not reached);
- the offsets the offline relocator bakes differ, for any program, from those the on-box relocator
  produces for the same build — compare the patched immediates byte-for-byte **before** the on-box
  path is deleted;
- PREVAIL **rejects** a program after relocation that it accepted before. It now sees real offsets
  rather than local dummies, so this is a live possibility and not a formality; a rejection means
  the proof was relying on the placeholder layout;
- the shipped binary still reports a `.BTF` section, or an armed CO-RE program stops firing — the
  first means the disclosure did not move, the second means relocation did not.

**Pre-registered order, because getting it wrong is a regression rather than a bug:** enforce
`build_min`/`build_max`/`expires_with` **first** (they are already signed and already ignored), then
add the layout digest, and only then remove the embedded BTF. The middle step needs a wire-format
bump — `SHIELD_BINDING_WIRE_MAX` is 128 and `16 + 112` is exactly 128, so the padding trick that got
`ctx_abi_version` in for free is spent (`shield_abi.h:33-40`).

**Status (2026-09-04): two of the four falsifiers discharged, on the build box.**

- **Falsifier 2 (offline ≠ on-box) is answered as a PROOF, not a sample.** The `.BTF` section
  extracted from the binary TMM runs is **byte-identical** to the standalone `tmm.btf` the offline
  tool reads — `0bd612b31196833c61a23a53d0317b3938ca26d3bd1e140d586456c96c021e37`, 6,711,626 bytes
  both. Same source file (`src/base/ls_core_relo.c` in TMM, `-DLS_CORE_RELO_TEST` offline), same
  input bytes, so the two cannot disagree. This also retires the *comparison* as the wrong test:
  it would have compared `ls_core_relo.c` to itself.
- **Correctness is therefore checked against an INDEPENDENT implementation instead.**
  `substrate/check_relo_baked.py` re-implements the whole CO-RE walk in Python — BTF parse, ELF
  section walk, `.BTF.ext` relocation records, name-based field resolution — and compares its answer
  to the immediate `ls_core_relo.c` wrote into the object. **8 of 8 relocations agree** across all 8
  programs in `shields/` + `surfaces/` (`make check-relo-baked TMM_BTF=…`). Reproducibility holds:
  relocating twice yields byte-identical objects.
- **The independent implementation's first version was WRONG, and that is the point of having one.**
  It walked the *target's* member indices; CO-RE resolves by field **name** from the program's own
  stub. It reported 7 confident mismatches against a C relocator that was right every time. Three
  stubs declare `{state, version_num}` and one declares `{state, flags, version_num}`, so index 1
  legitimately names different fields in different programs — index resolution cannot be right for
  both. Recorded rather than quietly fixed, because a harness that agrees for the wrong reason is
  worse than no harness.
- **One live hazard surfaced and is not fatal today:** `http_parse_ctx.state` is an **8-bit
  bitfield on a byte boundary**, read as a plain scalar by `http_observe` and `trace_stream`. Correct
  *by alignment only*. If `state` ever narrows, or a bitfield is inserted ahead of it, both programs
  begin reading neighbouring bits and PREVAIL, the signature and the arming gate all stay silent —
  the `gen_type_catalog.py` failure family. The screen for it is now part of the check.

**Falsifier 1 — DISCHARGED (2026-09-04).** The enforcement §15 showed was absent now exists and is
measured: `ls_build_gate.h`, 20 assertions off-TMM, and **9 of 9 on a live deployed TMM** (build
`a1c314d0`) via `env/scripts/bnk-test-build-gate.sh`. A program asserting a different build is
refused; the verdict is on the log with both ids. The pipeline additionally **refuses to sign** a
relocated program that has no build range, which is the coupling that makes baked offsets safe.

**Falsifier 3 — DOES NOT FIRE, and it is now a CONCLUSION rather than a hint (2026-09-04).**
`substrate/check_prevail_after_relo.sh`: 12 programs, **12 unchanged PREVAIL verdicts, 0 changed**.
Run twice — under clang 14 in the dev sandbox, then **on the build box under clang 18, the pinned
build compiler**, which is what makes it a conclusion (CLAUDE.md rule 5 records clang-14 passing a
program clang-18 refused). Identical result both times. Both directions are treated as findings — a
`PASS → REJECT` would mean the proof relied on the placeholder layout, and a `REJECT → PASS` would
mean a `reject_*` negative test had stopped testing anything. `reject_memory` stays REJECT.

**And a premise of this whole plan was wrong, in the helpful direction.** The plan said the
relocation stage faced an awkward cross-machine dependency because `tmm.btf` is produced on the build
box while clang and PREVAIL live in the dev sandbox. **The build box has PREVAIL** — `bnk-stage.sh`
stages it there and it runs — so that box holds all four things the stage needs: clang 18, PREVAIL,
the signing key and `tmm.btf`. There is no cross-stage handoff to engineer; the stage should simply
run there, which is also the only place its verdict is authoritative.

**Falsifier 4 — HALF DISCHARGED, and the remaining half is deliberate.** The measurable half is done:
`bnk-build-programs.sh` now runs **compile → relocate → strip → PREVAIL → sign**, and all **11
emitted artifacts carry 0 `.BTF` sections** (verified with `readelf` and the `--has-relos` probe,
~28% smaller); 7 of them had offsets resolved and baked. `bnk-bake-tools.sh` gained
**`LS_EMBED_BTF=0`**, which ships a binary with no type information.

**What is NOT done, and why it is a decision rather than a gap.** `LS_EMBED_BTF` still defaults to
**1**, so the deployed ELF still carries **6,711,805 bytes** of `.BTF` — measured on the running pod,
not assumed. The default has not been flipped because **this stage bakes no bytecode by design**, so
it cannot verify that the programs about to ship are stripped; flipping it would break any artifact
built without `TMM_BTF` set, and break it at **arm time on the cluster** rather than at build time.
Given this project's record of green builds shipping stale artifacts, the sequence is: bake once with
`LS_EMBED_BTF=0`, deploy, **arm a shield**, and only then change the default.

**So the claim to make today is bounded:** the mechanism to remove the disclosure exists, is measured
off-cluster, and is one deliberate flag away. It has **not** been shown to arm on a BTF-less binary.

**One caveat that survives all of the above.** The strip needs `llvm-objcopy`; GNU `objcopy` cannot
read a BPF ELF and fails in the way that matters least visibly — an unstripped program still loads
and verifies perfectly, so the only casualty is the disclosure the strip exists to remove. The
pipeline resolves the tool up front and **re-reads the object** to confirm the sections are gone
rather than trusting an exit code.

---

## Retired

### R1 · "Per-call cost cannot be obtained from a live TMM" — RETIRED

**Killed by:** fixing the benchmark op. It wedged the loader by allocating on a thread where
TMM's allocator freezes, and it timed the interpreter rather than the JIT. Both fixed; a bound
now exists. See `CONTESTED-PREMISES.md` #4.

### R2 · "Signal delivery is the blocker for hardware watchpoints" — RETIRED

**Killed by:** `prototype/watchpoint/wp_probe.c`. Ring-buffer delivery needs no handler in the
watched thread. The blocker turned out to be privilege instead, which is worse.
See `CONTESTED-PREMISES.md` #7.

### R3 · "The vendored uBPF revision is unrecoverable" — RETIRED

**Killed by:** `git rev-parse` in the vendored checkout. See `CONTESTED-PREMISES.md` #6.

---

## How this page is meant to fail

If a question here is answered and this page is not updated, the framework has stopped working
and the rest of the evidence discipline should be distrusted accordingly. That is deliberate:
a pre-registration that is quietly abandoned is worse than none, because it lends unearned
credibility to whatever survived.
