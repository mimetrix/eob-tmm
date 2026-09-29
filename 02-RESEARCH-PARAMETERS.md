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
`CAP_PERFMON` does not lift it — so an *independent* measurement still needs the same privilege
conversation as P4.

**PARTLY ANSWERED WITHOUT IT, 2026-09-05.** The trampoline already times itself with an `rdtsc`
pair, and an armed hook on a live TMM reports that per invocation — no PMU required. `poll_probe`
at `device_poll`, ~22.6k/s on a Xeon 8358 @ 2.60 GHz: **`cycles_min` = 96–98, ≈ 37 ns**. That is a
floor for the **whole armed path** — trampoline save/restore, call and return, dispatch, and the
JIT'd program — which is precisely what the ≤ 11 ns bench floor excluded. So the claim above moves
from "the floor is not a useful proxy, unknown" to "**the floor including the trampoline is ~3.4×
the program-only floor**".

**The falsifier does NOT fire, and the original question is still open.** It asked whether the real
per-invocation cost exceeds ~5× the floor. The *mean* here is 314–397 cycles (≈ 121–153 ns), which
is 3.3–4.1× — under 5×, but the number cannot be used: `cycles_max` hit **377,426** cycles (~145 µs),
so the tail is preemption and the mean is contaminated exactly as `load-path-scope.md` §7 says. An
independent method is still required to settle the mean, and `device_poll` is the poll loop rather
than a packet path — the trampoline transfers, the cache behaviour under traffic does not.

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

**`expires_with` — DEFINED AND ENFORCED, 2026-09-05, closing the last of the three fields named
above.** It is a **uint32 Unix epoch, UTC**: the program may not load at or after it, with `0` and
`0xffffffff` meaning never. No wire change was needed — the field was already present and already
inside the signature — whereas *deleting* it would have broken the 112-byte binding and every
signature in the field, which is why defining beat deleting. `sign_shield.py` now takes a date
(`--expires-with 2026-12-31`, `+90d`, `never`) and **refuses a deadline before 2020-01-01**, because
the loader will not trust a clock that early and could never enforce it.

**It fails OPEN on an untrustworthy clock, unlike the build gate, and the asymmetry is deliberate.** A
shield exists to stop a crash: refusing one because the container started before NTP ran converts a
clock problem into the outage the shield was preventing. A wrong build is a correctness error and must
refuse; a wrong clock is an environment error and must not. Both branches are asserted in
`check_build_gate.c` (32 assertions) precisely so this is not later "fixed" by someone reading it as a
bug.

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

**The default is now 0 (2026-09-04), and it waited on evidence rather than confidence.** The reason
to hesitate was real: this stage bakes no bytecode by design, so it cannot verify the programs about
to ship are stripped, and a wrong-order build would fail at **arm time on the cluster** rather than
at build time. What made the flip safe is case 5 of `bnk-test-btfless.sh` — a program that still
needs relocating is **refused with the cause named on the log**, so the wrong-order build now fails
with a message saying what to do instead of silently reading placeholder offsets. `LS_EMBED_BTF=1`
restores the old behaviour and now prints a warning that it is no longer the default.

**Falsifier 4 — FULLY DISCHARGED, on the cluster (2026-09-04).** `env/scripts/bnk-test-btfless.sh`,
**6 of 6**, build `1824611c`, image `tmm:NOBTF-CVE-2025-41414-DEMO-ONLY`. The running binary's section
headers, read inside the pod, hold **0 bytes** of `.BTF`. A stripped, relocated, signed program loads,
arms and **runs** — `fired 145,850 → 211,836 in 3 s, errors=0`, restarts=0 — carrying a baked offset
verified to patch `0 → 4`. And the fail-dark half holds: a program still carrying `.BTF.ext` is
refused with the cause on the log.

**One thing is still NOT shown, and it is a cluster fact rather than a phase 3 one.** No shield has
fired on an **HTTP** path with a BTF-less binary, because this cluster has no HTTP-parsing traffic
path up: `ltm-vs-basic` on port 80 is fastL4, so `http_parse_client_headers` is never called (10
requests returned 200 and moved `fired` by 0), and `h2-vs` on 8080 has no h2-speaking backend.
`device_poll` was chosen precisely to separate *does the mechanism run* from *is there traffic*.

**One caveat that survives all of the above.** The strip needs `llvm-objcopy`; GNU `objcopy` cannot
read a BPF ELF and fails in the way that matters least visibly — an unstripped program still loads
and verifies perfectly, so the only casualty is the disclosure the strip exists to remove. The
pipeline resolves the tool up front and **re-reads the object** to confirm the sections are gone
rather than trusting an exit code.

### P10 · Is an agent's tool call distinguishable at the syscall layer?

**Claim under test:** one tool call by an LLM agent produces an attributable syscall from an
attributable process, so a host-kernel program can bind it to a capability the proxy minted
([`cross-plane-intent-binding.md`](cross-plane-intent-binding.md) tier 1).

**Falsified if:** instrumenting a real agent stack (a LangGraph-style runtime, or an MCP server)
with `bpftrace` shows tool calls are **not** separable at the syscall boundary — a pooled HTTP
client, a sidecar, or a multiplexing language runtime leaves the kernel one long-lived socket —
and no cheap host-side signal recovers the boundary. That kills tier 1, and tiers 2 and 3 with it.

**Status:** unrun, and **it should be run before any other work on that document.** Cost is an
afternoon with `bpftrace` on any host; it needs no substrate, no build box and no cluster. This is
the same shape as `idea.md` §3.1 — the cheapest experiment is off-substrate and can kill the whole
programme.

### P11 · Can a capability be bound so on-host code cannot replay it?

**Claim under test:** a capability minted off-host can be verified in-kernel against context the
caller does not choose — cgroup, process lineage, destination, expiry — such that on-host code
without kernel privilege cannot spend it for an action the proxy did not authorize.

**Falsified if:** a cooperating process on the same host, **without** kernel privilege, causes an
unauthorized action — by reading and replaying the capability out of the environment, the request or
`/proc`; by inheriting it outside its intended process subtree; or by racing its expiry.

**Status:** unrun. Note the residual risk is conceded in advance rather than tested for: a
kernel-privileged on-host attacker defeats this by construction, so the claim is only ever *"the bar
is host kernel privilege **plus** an off-host proxy"*. Anything stronger is an overclaim.

### P12 · Do the two planes share a join key and a comparable clock?

**Claim under test:** an identity available to TMM at request time can be reconstructed host-side,
and the two planes' timestamps are close enough that a disagreement window is meaningful.

**Falsified if:** no such identity exists without a lookup that the join was supposed to replace;
**or** clock skew between the planes exceeds tool-call inter-arrival time, making the tier-2 window
unusable.

**Related and already open:** exporting the TSC-to-wallclock offset so userspace and host-side
timestamps align. `UFLOW_COOKIE` is TMM-side only and is a hand-written semantic derivation
(`mk_probe.py:30`), so it is not a join key as it stands.

---

### P13 · Can AI gateway events preserve operation identity across concurrent lifecycles?

**Claim under test:** the semantic event interface proposed in
[`ai-gateway-tracepoints.md`](ai-gateway-tracepoints.md) joins gateway-observed events to the correct
logical request, task, and upstream attempt through multiplexing, retries, disconnects, and task
continuation, while marking unavailable or untrusted lineage explicitly.

**Falsified if:** an event joins the wrong operation or tenant, an attempt is confused with its
logical request, or ambiguous lineage is reported as known. Compare event joins with an independent
test-client/upstream ledger; agreement between two consumers of the same event stream is insufficient.

**Status:** unrun, IDEA; protocol adapters and event schemas are not implemented by this proposal.

### P14 · Does an AI dispatch gate precede every protected upstream write?

**Claim under test:** a host-owned dispatch gate can reject a selected operation before its bytes
reach the upstream, including retry paths, while preserving unrelated traffic and protocol state.

**Falsified if:** any protected operation bytes reach the test upstream before or despite denial,
or rejection corrupts unrelated traffic. Exercise known-positive denials and allowed controls;
use upstream capture/receipt as the witness rather than the predicate's own match counter.

**Status:** unrun, IDEA; the existing function safe-return mechanism is not evidence of this new
protocol-aware action contract. Scope the first experiment to a named adapter and operation class.

### P15 · Do cancellation events distinguish intent from observed completion?

**Claim under test:** the proposed gateway events distinguish cancellation receipt, forwarding,
local cleanup, upstream acknowledgment, and any subsequently observed output.

**Falsified if:** forwarding alone is reported as acknowledgment or remote completion, or later
output is hidden by premature terminal accounting. Test upstreams that acknowledge, delay, or ignore
cancellation, comparing gateway events to the independent upstream ledger.

**Status:** unrun, IDEA. Remote computation stopping remains unknown without an appropriate remote
witness, even when the gateway's own cancellation path completes.

### P16 · Can semantic AI probes stay bounded and within an agreed traffic budget?

**Claim under test:** the proposed semantic probes and event publication have bounded inline work
and resource use, do not wait for a consumer, and meet an agreed workload-specific performance budget.

**Falsified if:** publication waits for a slow/stopped drainer, resource use escapes configured
bounds, or armed/unarmed comparisons exceed the pre-agreed latency or throughput budget. Exercise
representative streams, high event rates, retries, and consumer pressure; include context assembly
and publication rather than timing only the eBPF program.

**Status:** unrun, IDEA. Record workload, numeric budgets, event/sampling limits, and binary identity
before execution. Existing microbenchmark floors do not discharge this question.

---

### P17 · Does embedded-structure DSL traversal preserve the intended field access?

**Claim under test:** named embedded structs can be traversed alongside pointer edges without
mistaking inline bytes for a pointer; generated CO-RE accessors resolve to the intended scalar
and the relocated program passes the pinned verifier. See
[`broader-coverage-roadmap.md`](broader-coverage-roadmap.md) §5.

**Falsified if:** nested-only or mixed embedded/pointer access resolves the wrong field or offset;
an embedded edge adds a pointer dereference; NULL/unreadable pointer hops continue instead of
declining; or a bitfield/unsupported aggregate silently becomes a scalar. Require multiple fields,
typedef/qualifier wrappers, legacy pointer-only catalogs, and unchanged scalar behavior. Compare
relocations with independent expected offsets and execute fixtures where available; PREVAIL alone
cannot establish semantic correctness. Use build-box clang-18 and pinned PREVAIL on relocated bytes.

**Status:** exercised 2026-09-24. Native-offset/value fixtures pass pinned PREVAIL and both uBPF
engines; real-TMM objects agree on 12/12 independently checked relocations and pass final binding,
verification and signing. Updated authoring code/catalog installed on the build box. Three live
HTTP/1 probes yield 16/16, 0/16 and 16/16 matches, with independent pad restoration, successful
post-disarm traffic and zero restarts. See [`embedded-traversal-validation.md`](embedded-traversal-validation.md)
for separate fixture/real-TMM scopes, failed network preflights and limits; the HTTP/2
pointer→embedded expression was verified/signed but not executed live.

---

### P18 · Can the deployed image omit bulk catalogs without losing target binding?

**Claim under test:** build-side discovery resolves an eligible target into a small record inside
the signed program; the runtime admits only the exact full GNU build ID and that target/kind.
Entry and exit probes still load, arm, fire and disarm with no deployed hook/type catalogs or BTF.

**Falsified if:** a wrong-build record (including the same 32-bit prefix), a changed target/kind,
or an unauthenticated alteration is accepted; an already attached slot can be retargeted by reload;
disarm writes to an untracked address; or bulk catalogs/BTF survive in any distributable image
layer. Independently read patch bytes and exercise HTTP traffic; status counters alone do not
establish attachment/disarm. Preserve build-box `tmmtrace list`. Run pinned-toolchain admission
and signature tests before the live experiment. This is not a claim of concealed symbols or
reduced exploitability.

**Status:** exercised 2026-09-24 on build `c3b81927dfdcc31137cd8212b5e23bb85677a06c`.
Saved-layer audit, pinned fixtures, build-side discovery and live signed entry/exit checks passed;
wrong-build/kind/address/tamper, attached-kind and valid different-target reload were refused, with independent patch
readback and zero restarts. See [`catalog-free-deployment.md`](catalog-free-deployment.md) for
the exact cases, witnesses and limits; this is not universal coverage or a concurrency proof.

---

### P19 · Can synthetic AI exchanges traverse the deployed HTTP proxy intact?

**Claim under test:** an isolated fixture can pass MCP-shaped JSON-RPC initialization, sessioned
tool/resource calls and errors; A2A-shaped task creation/get/cancel and SSE; and inference-style
JSON/SSE plus a retry through the identified TMM. This first baseline uses HTTP/1 with the native
AI filters disabled. It tests forwarding, not protocol conformance or AI execution.

**Falsified if:** client/backend request IDs or body hashes differ, RPC/session/task assertions fail,
expected error/retry outcomes change, paced SSE arrives wholly buffered, any exchange bypasses the
proxy, or TMM restarts. Require 17 exchanges per worker, three concurrent workers, exact ledger
agreement, backend observation of the TMM SNAT IP, and a packet capture on the selected TMM.
SSE first-to-last event arrival must span at least 150 ms for deliberately 200 ms-paced events;
this is a buffering check, not a production latency budget. Record sources and runtime identity.

**Status:** exercised 2026-09-24, run `ai-4f9fb0add705`, build `c3b81927…`: 51/51 exchanges from
three concurrent workers reconciled, six paced SSE streams passed, expected errors/retries
preserved, backend SNAT and selected-TMM packet witnesses, stable pod and zero restarts.
See [`env/ai-traffic/README.md`](env/ai-traffic/README.md) for receipts and scope. The later eBPF
phase will compare its observations with these independent-of-substrate client/backend records.

---

### P20 · Can existing HTTP hooks produce a continuously drained, correctly correlated feed?

**Claim under test:** monitor-only eBPF records from supported HTTP hooks can be continuously
drained, decoded under an explicit schema and reconciled with the independent P19 fixture ledgers,
while delivering a useful internal signal unavailable through the relevant exposed iRules/WASM
interfaces within a pre-registered incremental poll-loop cost budget. Completed-request-header
observations at `fexit/http_parse_client_headers` are a calibration step; select the distinctive
signal by diagnostic value and demonstrated API-access gap. Validate response boundaries
separately. See [`ai-gateway-tracepoints.md`](ai-gateway-tracepoints.md)
§8.1 for the proposed hook shortlist, record contract and experiment order.

**Falsified if:** parser attempts are reported as distinct completed requests; any record joins the
wrong request/run; failed reads become plausible valid values; control traffic contaminates the
51-exchange count; schema/attachment changes silently mislabel records; or missing/duplicate records
are hidden. Request-header completion must be distinguished from response completion. Require a
single-run reconciliation first, then ten consecutive 51-exchange runs with one continuously
running collector and an intervening idle interval. Archive raw records, decoded records, source/
program identities, attachment history, ring counters and independent fixture receipts.

**Value/cost falsifiers, added 2026-09-24:** the selected supposedly unique observation is already
available through a relevant iRules/WASM interface at the required timing/granularity; the feed
cannot distinguish the internal condition it claims to explain; or the full capture/publication
path exceeds the pre-registered cost budget or waits for its consumer. Check interface coverage
with cached evidence. Compare unarmed, armed/no-publication, armed/publication and slow/stopped
consumer under P16 as part of the first signal's acceptance, not a deferred production exercise.
Successful export of ordinary HTTP fields alone does not satisfy this milestone.

**Security-use-case priority, clarified 2026-09-24:** select the first signal from
`ai-gateway-tracepoints.md` §8.2: control bypass/fail-open evidence, agent/session routing integrity,
inspection/release coverage or explanatory red-team evidence. The earlier streaming-stall
recommendation is superseded as the primary goal. Require controlled security-relevant positive
and negative cases, an independent outcome witness and the specific iRules/WASM visibility gap;
generic operational diagnostics alone do not complete P20. Proposed guardrail/policy fields require
an actual integration contract, not an assumption that they exist in the current TMM.

**Scope gates:** validate helper return semantics and collector consume/acknowledge/flush behavior
on the authoritative build box before assigning delivery guarantees. Keep-alive, fragmented headers,
concurrency and object reuse must challenge correlation before generalization beyond P19's current
one-connection-per-exchange workload. Response/stream/abort boundaries need separate cardinality
rules and independent expected outcomes. P13 covers broader semantic correlation; P16 separately
gates slow-consumer behavior, resource bounds and production performance claims.

**Status:** unrun, IDEA, registered 2026-09-24. No AI metadata probe or collector was deployed by
this planning update. Existing mechanism and traffic receipts establish prerequisites only.

**Previous selection, 2026-09-24:** delayed DLP allow/deny/timeout on the same paced
synthetic response, with host-enforced hold-until-allow and an independent client-content witness.
The [integration preflight](env/ai-traffic/INSPECTION.md) is MEASURED source/configuration inventory,
not an execution of P20. Adaptation/ICAP is a source lead; its ordinary result/timeout/action is
already exposed to iRules. Inference's analyzer-stream hold does not hold customer response data.
Establish a supported gate configuration and the specific visibility gap before implementation;
numeric workload/cost budgets are still unset. This choice supersedes the earlier routing-first
recommendation without claiming a DLP result.

**Priority changed by owner, 2026-09-25:** agent attribution is now primary. Register the
trust contract and adversarial cases in [`env/ai-traffic/ATTRIBUTION.md`](env/ai-traffic/ATTRIBUTION.md):
two authenticated agents, shared connections/concurrency, caller-ID collisions, spoofing, replay,
retries and scoped delegation. Authentication evidence supplies identity; an internal routing or
session binding alone does not. The first destination-side authentication fixture establishes an
independent ledger, not TMM authentication enforcement or differentiated eBPF visibility.
ICAP's bounded unarmed allow/deny/timeout cases have since passed (`GROUND_TRUTH.md`); retain
them as supporting outcome evidence. P20's attributed internal feed and P16's cost tests remain unrun.

**Prerequisite result, 2026-09-25 — MEASURED, SELF fixture:** `attribution-01` passes 23 expected
outcomes through the isolated TMM, including 15 attempts on one reused backend connection.
Authentication/delegation run at the destination; the principal map is configured fixture data.
This supplies the comparison ledger, not a completion of P13/P20 or a native-filter result.
See the [registered receipts](SOURCES.md#agent-attribution-fixture-2026-09-25) and attribution
contract for the six rejection cases and remaining trust/correlation limits.

**Consumer follow-up, same day — MEASURED, SELF:** the conservative ledger join passes
21 checks with synthetic candidate observations, including real fixture-proof A/B nonce
collision and replay, missing/lossy evidence and duplicate request identities. It refuses
ambiguous matches rather than joining by order. This advances the consumer only; a live
TMM request-lifetime/cardinality gate and differentiated internal facts remain unproven.
See [consumer contract/results](env/ai-traffic/ATTRIBUTION.md#consumer-result--attribution-join-01).

**Live scope follow-up, 2026-09-28 — MEASURED prerequisite, not P20 completion.**
The [registered parser-scope gate](env/ai-traffic/ATTRIBUTION.md#live-parser-scope-experiment)
now has a pinned live result: 66 calls/records for 59 completed headers; fragments
and an aborted header account for seven partial returns. Eight address tags span
multiple client connections. Header completion occurs before a paced body is sent.
These results falsify raw call count, address equality and header completion as
substitutes for request count, connection lifetime and accepted operation. All 59
attempted joins remain unknown. The next prerequisite is joint initialization,
cleanup and request-boundary observation with explicit missing-evidence cases.
No native AI-filter result, differentiated visibility or cost result is established.
[Receipts](SOURCES.md#attribution-parser-scope-2026-09-28).

**Lifetime follow-up, 2026-09-28 — MEASURED prerequisite, not P20 completion.**
The [registered three-hook gate](env/ai-traffic/LIFETIME.md) closes 71 observed
parser intervals in one HTTP/1 worker. It records 66 address-reuse pairs and
reconciles all 204 calls with output. Partial headers retain their attempt number;
an aborted header has an incomplete cleanup. Late/missed initialization keeps three
completed header attempts unknown. KERNEL witnesses show restored hook bytes and a
stable process. The next prerequisite is a bounded correlation value from a known
header attempt, joined to the authenticated authority ledger without using order,
address or time. Register that test before implementation. `request_scope_validated`
stays false; other parser callers, HTTP/2, multiple workers and cost remain open.
[Receipts](SOURCES.md#parser-lifetime-2026-09-28).

**Correlation follow-up, 2026-09-28 — MEASURED bounded join, not P20 completion.**
The [registered four-hook experiment](env/ai-traffic/CORRELATION.md) records
313 calls/events and 51 completed header observations. The join gives 42 accepted
operation matches, one authenticated rejection and eight unknowns. Missing births,
colliding nonces, a short nonce and forged authentication do not acquire guessed
actors. Reordered ledger input preserves results; five removed/invalid-evidence
checks stop attribution. All four hook sites are restored, with stable process
identity and zero restarts. Failed build/lint/formatting attempts are retained.

The result qualifies only canonical fixture HTTP/1 requests in a closed window:
512 header bytes, lifetimes 1–127, one worker and a trusted destination ledger.
It sets `bounded_join_validated=true` but leaves `request_scope_validated=false`.
The next work must register tests for missing-boundary recovery and broader
request/worker scope before generalizing. A specific internal fact unavailable
through existing surfaces and measured data-path cost are still required for P20.
[Receipts](SOURCES.md#bounded-request-correlation-2026-09-28).

**Controlled-gap follow-up, 2026-09-28 — MEASURED bounded recovery.**
The [registered gap tests](env/ai-traffic/GAPS.md) show why complete event output
does not prove that every boundary hook ran. A collector guard makes reported
breaks permanent for a result window. Native interpreter/JIT and live checks pass.
All 150 live requests complete; 1,023 calls reconcile with records. Missing-boundary,
pause and capacity windows stay unknown. After full reload, two new requests match;
a connection retained across reload stays unknown. No wrong-agent match is observed.

The live controller reports its own changes. Silent bypass, unreported changes,
missing controller history and stale collector restart remain unvalidated.
`request_scope_validated=false` remains required. P20 still needs a specific useful
internal fact beyond existing surfaces, broader worker/request scope and measured
data-path cost. Any stronger coverage claim needs a separately registered witness
that can detect the changes this collector cannot see.
[Receipts](SOURCES.md#controlled-correlation-gaps-2026-09-28).

**Owner direction, corrected 2026-09-28 — observe before choosing workload tests.**
The first response to the coverage request selected a 24-request wave: three agents,
two simulated instances each and four concurrent requests per instance. The owner
rejected that assumption-led approach before implementation or execution. The
proposal is withdrawn, not recorded as a failed measurement.

The next response made a real deployment a prerequisite for progress. The owner
corrected that too: **first design the probe and establish application-metadata
extraction; analytics follows later.** The [probe contract](env/ai-traffic/METADATA.md)
now specifies hook selection, readable values, field provenance, bounded reads,
availability and unsampled output attempts. Handler event codes and metadata
must remain visible without known agent semantics or fixture markers.

Source and packaged-binary discovery is MEASURED, with
[receipts](SOURCES.md#application-metadata-hook-discovery-2026-09-28). Three source
leads have no hook-index entries; the surrounding A2A/AIMCP handlers have padded
entries. Source also establishes lazy JSON parsing: not all fields are already
materialized. Handler event extraction and one root-object method-field path are
now MEASURED. The [field receipts](SOURCES.md#root-object-method-extraction-2026-09-28)
record exact live values, truncation, getter failure and budget exhaustion. The
AIMCP input did not call this getter and produced no method value. Event counts
alone did not meet the extraction goal; this correction remains in the probe record.
Falsifiers still include wrong or stale values, unknown events excluded, hidden
truncation, missing values called absent, application changes and loss presented
as complete capture. Other fields and broader extraction coverage remain pending.

The [later discovery plan](env/ai-traffic/COVERAGE.md) uses real activity to derive
representative tests. Selecting that deployment does not block probe design.

**Production streaming requirement, 2026-09-28 — IDEA.** The owner requires
continuous output for streaming analytics workflows. The
[service contract](env/ai-traffic/PRODUCTION-STREAM.md) places collection and
publication outside TMM. It proposes independent consumers, replay after durable
acceptance, bounded queues and explicit observation gaps. Pre-registered checks
cover multiple producers, process/collector replacement, queue/storage pressure,
schema changes, replay and sustained cost. Falsifiers are blocked forwarding,
unbounded buffering, wrong source identity, hidden loss or unavailable fields
presented as absent. The one-worker field test does not settle these questions.

**Local collector follow-up, 2026-09-28 — MEASURED subset, not P20 completion.**
The [pre-registered gate](env/ai-traffic/COLLECTOR.md) now has ten native checks
and a live method-value comparison. Commit precedes ring ACK; crash-window replay,
duplicate suppression, bounded retention, page-limit refusal and independent
HTTP consumers pass their stated tests. The legacy drain's delivery claim is
falsified, not inherited. One startup failure is retained: the ring is created on
first output. The corrected live run delivers eight method records to both
consumers and archives the ten-event journal before removing the fixture.
Multiworker ownership, silent-gap detection, authenticated publication, power-loss
durability, useful analytics and data-path cost remain open.
[Receipts](SOURCES.md#continuous-metadata-collector-2026-09-28).

**Separate-container follow-up, 2026-09-28 — MEASURED subset.** The
[registered container gate](env/ai-traffic/COLLECTOR-CONTAINER.md) now has eleven
native checks and one live traffic/replacement test. Normal stop and SIGKILL each
leave TMM forwarding. Both queued method values are recovered after collector
replacement. Two separate API-only consumers agree on eight method records and
ten journal events. A final controller key error is retained; evidence-only recovery
checks the journal and results without new traffic. The fixture is archived and
removed. Shared PID namespace, `SYS_PTRACE` and unconfined AppArmor limit security
isolation. Production ownership, full health history and sustained cost remain open.
[Receipts](SOURCES.md#separate-collector-container-2026-09-28).

**Token-cache method follow-up, 2026-09-28 — MEASURED subset.** The
[registered token-read gate](env/ai-traffic/TOKEN-METHOD.md) now extracts `tools/list`
on the AIMCP/JSON path. The initial attachment-helper hook produced zero records;
compiled inlining explains the gap. The revised JSON-completion hook passes pinned
PREVAIL and 68 native invocations. Thirteen live requests produce 26 cache records
through the existing separate collector, with exact bytes, explicit exclusions,
replay equality, restored hook and archived fixture removal. Bounds: four root
members, four fragments per selected read, 64 value bytes, 40 reads and 1,024 source
bytes. Literal first-match keys only; JSON filtering is required. Session fields,
protocol identity, complete coverage and data-path cost remain unvalidated.
[Receipts](SOURCES.md#token-cache-method-extraction-2026-09-28).

---

### P21 · Controller-published configuration snapshots — implementation in progress

Pre-registered 2026-09-25, before validation. A dedicated `ls_config_v1` ARRAY
view supplies bounded controller input independently of the legacy hash-map registry.
One invocation must see a complete, single revision or explicit unavailability;
program stores must never change the published image. Updates bind to a process
session, loaded-program instance and SHA-256, with compare-and-publish revisions.

**Falsifiers:** mixed records/revisions under concurrent publication; one invocation
switching revisions; program writes reaching another invocation/thread; a stale
session/instance/hash/expected revision accepted; malformed lengths or map shapes
accepted; an old program reading a replacement's configuration; a failed publication
changing the previous image; lookup allocating, waiting or retrying without a bound.
Exercise actual pinned clang-18/PREVAIL and uBPF interpreter/JIT, not just host helpers.
Socket framing and client error exit status are part of the contract. Bench evidence
does not establish live TMM integration or per-call cost. Armed/no-publication,
armed/publication and consumer-pressure cost budgets remain unset and unmeasured.

**2026-09-25 result — MEASURED, pinned build-box bench:** interpreter/JIT consistency,
10,000 concurrent publications/four readers, copy-write isolation, empty withdrawal,
sticky unavailability, stale/malformed refusals, socket fragmentation/truncation and CLI
failure exits pass. Existing map/helper regressions pass. The first PREVAIL refusal with
static map symbols is retained. [Contract](configuration-snapshots.md),
[receipts](SOURCES.md#configuration-snapshots-2026-09-25).

**Later the same day — MEASURED, isolated live SSA/Tao:** rebuilt/packaged `b8dc27f3…`
passes signed-load, missing-input, two revisions, five stale publication refusals, empty
withdrawal, identical-bytecode reload/new instance and revoke. Six armed phases total
48 requests/counter increments/events, zero reported drops/errors/safe returns; 52 exact
HTTP responses including baseline/disarmed requests. Kernel executable hash and two
call/NOP transitions corroborate the running binary and attachment, with no restart.
The wrong-opcode recorder failure is preserved. Live publication pressure, cross-UID
negative tests, failure-path initialization/reclamation and performance remain open gates.

### P22 · New-user eBPF tutorial

Registered 2026-09-25 before running the tutorial checks. The original `substrate/template.c`
combined configuration, mutable maps, named-field reads, clock-based sampling,
event output and entry verdict selection. An exit build reads the return value.

**Falsifiers:** either variant fails pinned PREVAIL; interpreter and JIT disagree;
unresolved field offsets produce the expected native values; missing/invalid input
selects SAFE_RETURN; sampling changes the verdict; an output refusal stops policy
evaluation; a reset/reload inherits the old count; exit bytecode dereferences an
argument object or selects SAFE_RETURN. Test native layouts that differ from the
program's local declarations. Keep bench and target-binding results separate from
live traffic and cost claims. The tutorial does not establish request identity.

**Result — MEASURED, pinned bench and target binding:** both variants pass
PREVAIL and interpreter/JIT checks. Four relocated offsets match native C
offsets. The unrelocated negative fails as expected. Input generation, event
decoding and malformed-length refusal pass. Packaged entry and exit binding,
exit admission and final PREVAIL pass. A one-entry hash-map lookup failed;
the template then used 256 entries. All attempts are
[retained](SOURCES.md#ebpf-tutorial-2026-09-25).

**Later live result — MEASURED; full success FALSIFIED:** entry and exit complete
14 phases on the packaged TMM. All 118 HTTP responses are exact; 112 armed calls
produce 112 program records. Configuration, counters, reset, deletion, monitor
selection and cleanup checks pass. Both sampling phases fail: eight records appear
where zero are required. The output bridge reports failure after delivery and
success after a full-ring drop. The earlier bench used a substitute output sink.
An existing fixture also exposes stale map storage after revoke and a changed map
layout. A separate fixture permits the remaining checks; it does not fix reuse.
Build-box reproducers confirm both host defects. Keep these tests failing until
the host is corrected and the packaged live path is tested again. Cost remains
unmeasured. See contested premises §§23–24 and the same receipt table.

**Revised contract, registered before the repaired live run, 2026-09-25:**
the owner requires unsampled observability. Schema 2 removes the optional
interval. The program must attempt one record per call, including diagnostic
paths. Schema 1 and a nonzero reserved interval word must be refused as input.
The default interval in schema 1 was already zero; sampling was not the default.

**Repair falsifiers:** a small HASH table loses an inserted key; deleting a key
breaks lookup or update of a colliding key; an old map reference reaches a new
generation; reset succeeds beneath an active reader; replacing two output maps
with the one-entry tutorial HASH fails; revoking a second slot changes the active
slot's count; successful output returns an error; dropped or disabled output
returns success. In the isolated live run, require 112 tutorial calls and 112
decoded tutorial records, plus eight precursor calls and 16 precursor records.
Require 126 exact HTTP responses, three observed call/NOP cycles, zero reported
errors or drops, and a stable process. Any mismatch fails the run. This count
test does not establish a loss-free transport under pressure or a per-call cost.

**Repair result — MEASURED:** pinned host and configuration checks pass. Both
one-entry tutorial variants pass interpreter/JIT, PREVAIL and packaged binding.
The isolated live run passes every count and state check registered above:
126 HTTP responses, 112 tutorial records, 16 precursor records, three restored
hook cycles and no restart. The output bridge's delivery/drop/off results are
tested natively against the real bridge. Live output-pressure and cost tests
remain open. [Retained records](SOURCES.md#unsampled-observability-repairs-2026-09-25).

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
