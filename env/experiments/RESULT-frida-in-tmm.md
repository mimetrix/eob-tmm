# Frida-gum inside TMM — experiment result, 2026-08-17

**It works, and it hooks what pad-based arming structurally cannot.**

This experiment was run to settle an assertion I made in `widening-plan.md` and had no
evidence for: that adopting bpftime "means Frida-gum ... inside TMM's data plane [and]
Frida installs its own inline trampolines, which collides with pad-based arming and
with TMM's memory layout."

That claim is now disproven.

---

## What was run

**Stage 1 — a TMM-shaped harness** (`frida-tmm-shape.c`): static, `-no-pie`, 8 threads
hammering an unpadded function, hook installed and removed mid-flight.

```
target entry, before   f3 0f 1e fa 48 89 f8 ...   <- NOT padded
target entry, hooked   e9 e3 4a 8b 00 66 90 ...
target entry, detached f3 0f 1e fa 48 89 f8 ...

Q1 REACH    hook an UNPADDED function      : PASS
Q2 LIVE     attach under 8-thread load     : PASS
Q3 CORRECT  no corrupted results           : PASS  (0 wrong of 10,094,942)
Q4 RESTORE  entry bytes restored on detach : PASS
```

**Stage 2 — inside TMM proper** (`substrate/ls_frida_probe.c`), because a shaped
harness cannot test TMM's allocator, its `.text` layout, or its real instruction
sequences. Target: `EVP_EncryptUpdate` at `0x1aa0340` — an **OpenSSL** function, i.e.
exactly the population that has no compiler pad.

```
ls_frida: EXPERIMENT --- attaching frida-gum to 0x1aa0340
ls_frida: gum_init_embedded() returned
ls_frida: attach(0x1aa0340) -> 0 OK
ls_frida: entry now e9 c3 8c f9 02          (jmp rel32 over endbr64; push %r13)

pods Running, restarts=0
VIP: HTTP 200 after 20 requests
```

---

## What this settles

1. **`gum_init_embedded()` survives TMM's allocator.** This was the biggest expected
   failure: TMM aliases `malloc` to a per-core allocator whose spinlock is never
   `spin_init`'d on threads TMM did not create, and we lost a day to exactly that with
   our own loader thread. Frida allocates heavily at init. It worked.
2. **Frida hooks unpadded functions in a live TMM.** `EVP_EncryptUpdate` is one of
   OpenSSL's 1,781 linked symbols, none of which carry the pad. **Pad-based arming can
   never reach any of them.** This is the CVE reachability blocker, and Frida-style
   attach solves it without privilege, without debug registers, and without the
   four-per-thread ceiling that hardware watchpoints impose.
3. **TMM keeps serving.** HTTP 200, zero restarts, with the patch in place.
4. **No symbol collisions** — 7,779 frida exports against TMM's 47,255.

---

## What it does NOT settle, stated so nobody over-reads it

- **Hits were not counted.** The traffic is plain HTTP; `EVP_EncryptUpdate` is on the
  TLS path and was likely never called. `ls_frida_hits()` is also not wired into the
  STATUS reply. **Attach succeeded; invocation was not observed.**
- **One function.** Relocation safety depends on WHICH instructions get displaced, and
  TMM has ~74,000 of them. The dangerous case is a branch target inside the first five
  bytes. One success proves the mechanism, not the population.
- **No per-hit cost measured.** Nothing here says what a Frida hook costs versus our
  direct-call trampoline, and that difference is the whole argument for keeping pads on
  high-frequency paths.
- **Integration cost is real and quantified**: **414 new mutable globals** into TMM's
  whitelist, and the binary grew 203MB -> 224MB. TMM's whitelist exists specifically to
  control global mutable state; adding 414 entries is a review burden, not a detail.
- **This linked frida-gum only**, not bpftime. bpftime additionally brings LLVM.

---

## What it changes

The recommendation in `hook-types-plan.md` said hardware watchpoints are "the mechanism
the CVE use case actually requires". **That is now doubtful.** Watchpoints need
privilege, are limited to four per thread, and deliver via a signal handler in a
run-to-completion poll loop. Frida-style attach needs none of that and reaches the same
unpadded code.

The honest position: **pads remain right for high-frequency paths** (unbounded sites, a
direct call, no privilege — see `hook-types.md` §2.5), and **Frida-style attach is now
the leading candidate for CVE reachability**, displacing watchpoints.

The next question is no longer "does Frida work in TMM" — it does — but **"what
fraction of TMM's ~74,000 function entries can Frida relocate safely?"** That is
measurable statically against the real binary and is the thing that should be measured
before anything is built on this.

---

## Supply chain — the gate this experiment skipped

Asked "how do I know there isn't backdoor code in this framework", and the honest
answer is **you don't, and nothing done here would tell you.** The library was
`curl`'d as an 89MB prebuilt binary from a GitHub release and linked into a security
appliance with no verification of any kind.

**What came in — 753 object files, nine upstream projects:**

| component | exported symbols | what it is |
|---|---|---|
| GLib | 4,539 | full runtime: main loops, threads, file I/O, spawn |
| gum | 1,073 | the instrumentation core --- the only part actually wanted |
| PCRE2 | 73 | regex engine |
| libunwind | 67 | stack unwinding |
| Capstone | 45 | multi-arch disassembler, incl. AArch64 tables on an x86-64 appliance |
| GIO / GObject / GVDB | 27 | I/O, object system, embedded database |
| zlib, liblzma | --- | `adler32`, `tuklib_*` |

Artifact sha256 `0987dd51e9901a6dddd9d55bc9ef02cd90d95012a4947e29dab942ec7f5348b7`,
**checked against nothing**. No signature, no reproducible build, no SBOM, no CVE scan.

**One check was run and came back clean:** no listener on frida's default control ports
(27042/27043) inside the running TMM --- only F5's own `qkview-collect`. Consistent
with `gum` being the library rather than `frida-server`, but that is one negative
result, not a clearance.

**What diligence would require:** verify against a published digest or build from
source; SBOM across all nine upstreams with CVE tracking (GLib and PCRE2 both have
histories); audit what `gum_init_embedded()` starts, since it brings a GLib main loop
and thread machinery into a run-to-completion data plane; and strip what is unused.

### The strategic consequence, which runs OPPOSITE to the capability result

- **Capability gate: Frida wins.** It reaches OpenSSL. Pads structurally cannot.
- **Trust gate: uBPF wins, and not narrowly.** A few thousand dependency-free lines one
  person can read in a week, against 753 objects across nine projects.

Both gates are real and this experiment only ran the first. The position worth
defending is therefore narrower than "adopt bpftime": **keep uBPF as the runtime**, and
if unpadded reach is needed, ask whether the ATTACH MECHANISM alone can be borrowed ---
Frida's relocator is a small fraction of those 753 objects --- rather than adopting the
whole stack. That is a far smaller thing to audit.
