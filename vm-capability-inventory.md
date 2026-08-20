# The TMM eBPF VM: what it can do, what it cannot, and what each gap costs

Written 2026-08-18. A companion to `hook-types.md` (which asks *what events can we attach
to*) and `demo-options.md` (*what questions can we answer*). This one is the flat
inventory across every axis, measured from the code rather than recalled, with bpftime as
the comparison because it is the mature implementation of the same idea.

**Every number below was read out of the source or the shipped binary.** Where something
is unmeasured it says so.

---

## 1. Hook types — one event source

| type | state | evidence |
|---|---|---|
| **Function entry, pad-patched** | **live** | `rst_why` armed on a running TMM; entry bytes verified in `/proc/<pid>/mem` going `90 90 90 90 90` → `e8 …` → back byte-identical |
| Two pad shapes | live | `endbr64`+5 nops at +4 (indirect-call targets); 5 nops at +0 (statics, `.isra`/`.constprop` clones). `http2_stream_abort` is the second kind |
| Concurrent hooks, different shapes | live | per-slot trampolines, 12 expansions |
| Live arm / disarm | live | `OK ARMED LIVE` / `OK DISARMED LIVE`, restore asserted byte-identical |
| Designed-in call site | **retired** | the HTTP tracepoint; rolled back because iRules already saw every field |
| Exit / return probes | **absent** | needs per-thread per-depth return-address storage, a depth cap, and a give-up path for `longjmp`/unwind/`noreturn` |
| Timer / periodic | **absent, and see §5** | `ls_prep` already runs on a TMM timer, so the event source is nearly free |
| Hardware watchpoint | **prototyped outside TMM**, 2026-08-20 | removes the pad requirement entirely, so it reaches code F5 does not compile. Measured: `CAP_SYS_ADMIN` required (`CAP_PERFMON` is refused at `perf_event_paranoid=4`), exactly four concurrent, 501 ns/hit aarch64 and 4,755 ns/hit in an x86 KVM guest — viable for rare high-reach events, not per-request. `prototype/watchpoint/` |
| …delivered by a signal | **FALSIFIED** | this row previously said watchpoints "need signal-context delivery", which was the objection to them. They do not: samples land in a ring buffer that another thread drains, with nothing installed to catch a signal. `CONTESTED-PREMISES.md` #7 |
| PMU counters | absent | a *helper*, not a hook type — and the direct answer to the per-call cost, of which only a **floor** is measured (≤ 11 ns, bounded by the timer rather than the program). Instructions-retired would give the data-path figure and is not subject to the preemption artefact; `perf_event_paranoid=4` blocks it today |
| XDP / tc / socket / LSM / cgroup | **not applicable** | kernel-plane program types; TMM has its own userspace data path |

**The honest headline stays:** kernel eBPF attaches to roughly ten kinds of event. We
attach to one, on functions the build padded.

---

## 2. Context shapes — three, and a hard ceiling

The ctx ceiling is **96 bytes, inclusive**, and that is now *measured* rather than
folklore. Compiling programs that read the **last** byte of ctx structs from 64 to 256
bytes: byte 95 of a 96-byte ctx verifies; byte 99 of a 100-byte ctx is refused with

```
Upper bound must be at most 96 (valid_access(r1.offset+99, width=1) for read)
```

An earlier test that read only byte 0 passed at **every** size — proving nothing, because
the bound is on the **access**, not the declared struct.

| shape | what the program sees | records built this way |
|---|---|---|
| Generic 5-register | `arg[0..4]` as flat scalars | the shield slot. Useless for most TMM functions, which take pointers a verified program cannot chase |
| Typed from direct arguments | the host flattens arguments | reset (92 B), ssl__err (96 B), h2abort (48 B) |
| Typed by host-side dereference | the host chases the pointers | ALPN — `ssl_alpn_match` derives its bytes from `sc`, so `ls_ctx_alpn.c` repeats that derivation in the ssl module's include world |

The third is the general escape hatch, and it is why an unfamiliar hook is a day of work
rather than a line of config.

---

## 3. Maps — one type, and the limits are real

| property | value | source |
|---|---|---|
| Types | **hash only** (`BPF_MAP_TYPE_HASH`) | `ls_map.h:72` |
| Maps per program | **4** | `LS_MAP_MAX` |
| Entries per map | **256** | `LS_MAP_ENTRIES` |
| Key size | ≤ **16** bytes | `LS_MAP_KEY_MAX` |
| Value size | ≤ **32** bytes | `LS_MAP_VAL_MAX` |
| Storage | **per TMM thread**, mmap'd, never grown | lock-free by construction |
| Collision policy | **evict the incumbent, counted** | a bounded table that blocked would put an attacker in control of the data path |
| Identity | the **symbol name** (since 2026-08-18) | same name+shape shares deliberately; same name+different shape is refused |

**Missing, in value order:**

- **Array maps.** Trivial — index, no hashing, no eviction — and the right shape for what
  the two newest programs actually want: count by TLS alert code, count by
  `enum http2_error`. A 256-entry hash table over a dense 16-value key space is the wrong
  tool and burns the table.
- **Iteration** (`bpf_for_each_map_elem`). Absent, and this is *why* any rollup has to use
  fixed known keys: a program can accumulate state and never summarise it.
- **Per-CPU maps.** Ours are already per-thread, so this is mostly a naming difference —
  but it would let a consumer know the sum is intended rather than inferring it.

---

## 4. Helpers — three

```c
ubpf_register(vm, 1, "bpf_map_lookup_elem", …)
ubpf_register(vm, 2, "bpf_map_update_elem", …)
ubpf_register(vm, 3, "bpf_map_delete_elem", …)
```

That is the entire surface. Ids 1/2/3 with the standard names and semantics, which is
what lets PREVAIL verify these programs with **no platform work at all**.

**The two absences that matter, and they are related:**

**`bpf_ktime_get_ns` — there is no clock.** A program cannot know what time it is, so it
cannot express "N per second", any rate limit, or any decay. This is not a nicety: it is
why `rate_watch`'s threshold means *"this site fired more than 5 times ever"* rather than
*"recently"*. The counter never resets, so `safe_returns` answers a question nobody asked.

**Program-controlled emission.** `ls_tp_ring_publish` is called from `ls_tp_emit.c` — the
**host** publishes a record for every event, after the program runs. The program cannot
say *"this one is not interesting."*

> **Together those two retire the parked timer hook.** A program with a clock and an emit
> helper does its own rate limiting and its own summarising, with no new event source and
> no new dispatch path. That is a smaller change than the timer for strictly more
> capability, and it is the single best extension available.

**And the caveat that governs every helper added.** Helpers are exactly where PREVAIL's
assumptions and uBPF's execution must be made to agree — the failure mode uBPF's own
`docs/VerifiedPrograms.md` describes: *"PREVAIL assumes that r1 points to a valid memory
region"* while uBPF *"doesn't enforce any particular context layout"* and *"memory safety
depends on the program"*. Each new helper is another place the verifier proves something
the runtime must actually enforce, so each wants the treatment `ls_map_glue.h` got — a
descriptor check at the crossing — not a bare `ubpf_register` call.

---

## 5. Verdicts, modes and the safe value

| | |
|---|---|
| Verdicts | `LS_FALLTHROUGH` (run the body), `LS_SAFE_RETURN` (skip it, return the declared safe value) |
| Modes | `DISABLE` (0), `MONITOR` (1 — evaluate and count, apply nothing), `ENFORCE` (2) |
| Safe value | **hardcoded 0**, with a `TODO(f5)` — it belongs to the safe-return policy table |

**The live limitation, stated because it is an admission-time hazard rather than a
runtime one:** the trampoline moves the safe value to `rax`, which is correct only for a
return type that fits in `rax`. A struct returned by hidden pointer, or anything using
`rdx:rax` or the SSE return registers, needs its own path. Returning a *wrong* safe value
is worse than not shielding — it converts a crash into silent misbehaviour.

---

## 6. Egress — per-thread rings, host-published

| property | value |
|---|---|
| Rings | **16 max**, one per thread, single-producer |
| Ring size | **64 KB** each (~700 reset records) |
| Full policy | drop and **count**, never block — TMM must not depend on the drain agent |
| Consumer | `ls_drain`, a separate process sharing only these bytes; emits JSON lines |
| Schemas | 2 = HTTP (44 B), 3 = reset (92 B), 4 = ssl__err (96 B), 5 = h2abort (48 B) |

**Dispatch is on SCHEMA, not hook id** — as of 2026-08-18, and that was a bug fix. It
read `hook_id == LS_TP_HOOK_RST`, which is id 4 alone, so records from the other three
reset functions fell through and printed as raw hex.

---

## 7. Program identity and admission

| gate | state |
|---|---|
| **Section + function must agree** | **enforced.** PREVAIL selects by ELF section, uBPF by function symbol — two different identities, and in an object with several functions they can denote different code |
| `ctx_abi_version` | **enforced** at load, msg offset 121 |
| Build-ID match | **enforced** at arm, since 2026-08-18 — the index carries the build id it was generated from, compared against `/proc/<pid>/exe` |
| Ambiguous symbol name | **refused** — 591 names in this build have 2–21 entries each |
| Arming a slot with no program | **refused**, since 2026-08-18 |
| **Signature verification** | **enforced** at load, since 2026-08-20 — Ed25519 over the 112-byte binding, checked in TMM against a key compiled in; unsigned, re-signed and altered programs refused |
| Control-plane audit trail | **enforced** at every operation, since 2026-08-20 — one record per op with the target, the program hash, the serving binary's GNU build ID, and the verdict the caller received *verbatim*. Not tamper-evident by format: durability is the sink (the pod log, collected off-box) |
| Peer identity on the loader socket | **PARTIAL.** The program is authenticated and the *process* that asked is kernel-attested (`SO_PEERCRED` pid/uid/gid, which the peer cannot forge). What is absent is a **person**: everything here is uid 0, and under `kubectl exec` the process belongs to an API call TMM cannot see. Lab only for this reason |
| Revoking a signing key | **ABSENT.** The verifying key is compiled into the binary, so revocation is a rebuild |
| Per-invocation budget | pass exists (`budget_pass.py`) but is not enforced at admission |

---

## 8. Execution

- **Interpreter and JIT both available.** `LS_VM_JIT=1` in the lab.
- **The JIT never consults the bounds callback.** So a JIT'd program's map and ctx access
  is unchecked at runtime — the interpreter and the JIT do not agree on safety, and the
  lab runs the JIT. This is the most under-advertised limitation in the system.
- uBPF's instruction limit *"has no effect on JIT'd programs"* and does work in the
  interpreter.

---

## 9. What NOT to take from bpftime

- **LLVM JIT.** A large dependency inside a data-plane process heading for a formal TMA.
  uBPF's simple JIT is a few thousand auditable lines; that is most of the argument for
  the whole approach.
- **Shared-memory cross-process maps.** Ours are per-thread and lock-free by
  construction. Sharing means a lock on the poll loop, which is the one cost this design
  cannot pay.
- **Syscall tracepoints.** TMM barely syscalls on the data path.
- **Frida-gum inline hooking.** Tested 2026-08-17: it works, hooks unpadded OpenSSL, and
  survives TMM's allocator. Reverted on the supply-chain gate (753 objects, 9 projects,
  unverified) — not on capability.

---

## 10. Ranked: the extensions worth making

**Re-ranked 2026-08-19.** `bpf_probe_read` moved to the top after testing showed PREVAIL
admits it unchanged. It outranks everything below because it is the only item that removes a
**rebuild** from the critical path rather than adding expressiveness within one.

| # | extension | why | size | state |
|---|---|---|---|---|
| 1 | **`bpf_probe_read`** | **Removes the per-hook ctx builder, and therefore the rebuild.** A verified program cannot chase a pointer, so today the host dereferences in C compiled into TMM — which is why a hook with a new argument shape costs a build cycle. With this the program chases pointers itself and the generic five-register context covers arbitrary hooks: a new hook shape becomes a new *program* | one helper + a range check | **BUILT 2026-08-19** |
| 2 | **`bpf_ktime_get_ns`** | there was no clock at all, so every threshold meant "ever" rather than "recently" | one helper | **BUILT** |
| 3 | **program-controlled emit** | the host published per event; a program could not decide what was worth reporting. With 2, retires the timer hook | one helper | **BUILT** (`bpf_perf_event_output`) |
| 4 | **array maps** | the right shape for dense small key spaces — alert codes, error enums | small | open |
| 5 | **`.data`/`.rodata` relocation** | a threshold becomes a load-time parameter rather than a recompile; the relocation callback already exists | small | open |
| 6 | **PMU as a helper** | the direct answer to the per-call cost that gates every review. `rdtsc` is preemption-polluted; instructions-retired is not | low — measurement, not mechanism | open |
| 7 | **ctx-builder generation from DWARF** | now a convenience rather than a necessity. Tiers 1–2 (scalars, `const char *`) are fully mechanical; tier 3 (which fields of a struct matter) is semantic; tier 4 (`UFLOW_COOKIE`) cannot be derived at all | medium | open (scope item 6) |
| 8 | **map iteration** | a program can accumulate but never summarise its own state | medium | open |
| 9 | **exit probes** | return values: latency inside TMM, and what a function *decided* rather than what it was asked | medium-high — the first item that can corrupt control flow | open |

### Why `bpf_probe_read` outranks the rest

Before it, the cost model had two tiers:

> a new question on an **existing** hook shape — minutes, live, no restart
> a new hook **shape** — a rebuild

The second tier existed only because the dereferencing had to happen in host C. `probe_read`
collapses it: `substrate/shields/generic_probe.bpf.c` takes the generic register context,
dereferences TMM's `__FILE__` pointer itself, and recovers the same filename the typed reset
record carries — with **no host-side code for that hook**.

**What it does not do, so the claim stays bounded.** The generic context carries five
registers; `rst_why`'s sixth argument is the cause string, which only a typed builder sees.
And derivations like `UFLOW_COOKIE` — a macro hashing three fields into a flow identity — are
judgement, not type information, and no generator or helper produces them. So `probe_read`
removes the rebuild, not every reason to write a builder.

**Fault safety is the whole of the engineering.** The helper must return an error for a bad
address, never fault. The kernel uses its page-fault handler and a fixup table. Userspace has
three options and only one is affordable in a poll loop:

| approach | per-call cost | catches |
|---|---|---|
| **range-check against mappings cached per thread** | two compares | NULL, unmapped, wild, wrapping, straddling — the common case |
| `process_vm_readv` on self | a syscall per read | everything; far too slow |
| `SIGSEGV` handler + `siglongjmp` | async-signal-safety inside run-to-completion, and the handler is **process-wide**, colliding with TMM's own crash handling | everything |

The range check is what shipped. It does **not** catch a pointer that is mapped but
semantically wrong — and neither does a hand-written ctx builder, which dereferences on trust
today, so this is a bound where there was none rather than a regression. The snapshot is
per-thread, built from `/proc/self/maps` on first use, and refreshed once on a miss before
refusing, because TMM `mmap`s after init and a stale snapshot would refuse a legitimate read
forever.
