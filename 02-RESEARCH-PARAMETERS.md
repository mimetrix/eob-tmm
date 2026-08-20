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

### P6 · Can a program be refused unless it carries a valid signature?

**Registered before the work, 2026-08-20.** The gap this closes is the largest one on
`GROUND_TRUTH.md`: the loader accepts anything and prints `unverified=yes` on every load.

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
