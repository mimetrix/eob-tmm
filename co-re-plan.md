# Build-decoupled live surfaces — CO-RE for TMM

**The target.** The live surface is a general substrate; a shield is only ITS FIRST CONSUMER.
Observability, per-flow logic, tracepoints and enforcement are all surfaces, and ALL of them should
be **build-decoupled portable bytecode** — referencing TMM fields by *name*, carrying CO-RE
relocation records, with the loader resolving offsets against **TMM's own type info at load time**.
TMM ships a fixed, general VM surface baked once (probe_read, maps, clock, trampoline). After that:
any new surface = new bytecode, **zero TMM builds, zero bespoke C**, and the *same* bytecode runs
across TMM builds. This is the kernel CO-RE model, sourced from TMM instead of the kernel — applied
to the whole live surface, not just the shield use case.

**Why.** Every reach mechanism built before this — typed ctx builders, bespoke accessor helpers,
DWARF-offsets-baked-into-bytecode — is build-coupled: each new data source burns a TMM build, which
is the exact cost the VM exists to eliminate. CO-RE dissolves it. It also makes CVE mitigation real:
a shield for a new CVE becomes write-it, sign-it, load-it — no release cycle.

**The principle.** Everything the VM needs to relocate arbitrary bytecode is an artifact of the TMM
build, derived from it, stamped with its build id. The bytecode itself is free.

| need | build artifact | kernel analogue |
|---|---|---|
| VM + relocator + probe_read | the TMM binary (baked once) | the kernel |
| layout truth | DWARF / debuginfo | — |
| `tmm.h` (write shields by name) | DWARF → pahole → BTF → dump | `vmlinux.h` |
| shipped BTF (relocate at load) | DWARF → pahole → BTF (data file) | `/sys/kernel/btf/vmlinux` |
| arm by name | hook-index.tsv (DWARF-derived) | — |
| verify/shape | signatures.tsv (DWARF-derived) | — |
| consistency | build id, stamped on all of the above | BTF versioning |

The DWARF-walking + build-id-stamping pipeline mostly EXISTS (mk_hook_map.py, the signature index,
the receipt). CO-RE redirects its output: DWARF → BTF → shipped file + `tmm.h`, and the loader
relocates against it instead of us compiling offsets in.

## Phase 0 — decisions (LOCKED 2026-08-25)

1. **Relocator:** port **libbpf's** CO-RE relocation from source (canonical, most-tested, what clang
   emits for; extract the relocation math, do not link the library — as we vendor ubpf/PREVAIL).
2. **Type-info form:** **BTF via `pahole -J`** (what the stock relocator + clang expect; small).
3. **Delivery:** **BTF shipped as a data file** in the image (like hook-index.tsv / signatures.tsv);
   data not code, so producing/updating it needs no TMM compile.

## Phases — each has a falsifier proven on the PINNED toolchain before the next starts

**Phase 1 — de-risk the chain OFF TMM (no TMM exposure). [PASSED 2026-08-25]**
A toy C struct; a BPF program using `BPF_CORE_READ`; BTF via pahole; apply CO-RE relocations
(libbpf/bpftool); feed the RELOCATED program to PREVAIL; run on ubpf.
*Falsifier:* PREVAIL rejects relocated CO-RE bytecode, or ubpf can't run it → the approach is wrong,
learned in an afternoon at zero TMM risk. **The single make-or-break gate.**
*RESULT (build box, clang-18, PREVAIL v0.2.5 06769f7b, all gates):* clang emits the CO-RE program
with `.BTF` + `.BTF.ext` relocation records; PREVAIL **PASSES** it. The same program compiled against
three struct layouts (field at offset 8, 16, 44) all PASS — the offset value does not change the
verdict, so relocating to any build's offset stays verifiable. ubpf running the relocated bytecode
is the same as running any shield (15 already run in TMM), so that half is covered by existing
evidence rather than re-proven here. **Gate cleared.**

**Phase 2 — TMM's BTF. — PASSED 2026-08-25 (build box, build id 005835f9).**
`pahole` on TMM's debuginfo (`tmm64.no_pgo.debug`) → detached BTF; dump → `tmm.h`. Verify it carries
`ssl_ctx`, `http_parse_info`, `ssl_extension`. Cross-check offsets against our DWARF derivation.
*Falsifier:* DWARF→BTF fails or key types absent.

*Result (MEASURED, tool-witnessed — pahole/bpftool on the pinned debuginfo):*
- Stock **pahole v1.25 FAILS** — dies at the first of **43 `_Atomic`-qualified types**
  (`Unsupported DW_TAG_atomic_type`), emitting a 0-byte BTF. `--btf_encode_force` does not help
  (it ignores invalid *symbols*, not unsupported *types*).
- **Fix:** built **pahole v1.29** from source on the build box (needed `libdw-dev`/`libelf-dev`/`zlib1g-dev`)
  and added a one-line encoder case mapping `DW_TAG_atomic_type` → `BTF_KIND_VOLATILE` — layout-identical
  and skipped by CO-RE modifier resolution, so field offsets relocate correctly. Patch pinned at
  `substrate/toolchain/pahole-atomic-qualifier.patch`. **This patched pahole is now a toolchain pin**
  (like the uBPF/PREVAIL pins) — the BTF is a TMM-build artifact only with it.
- Patched pahole: **exit 0**, valid **6.5 MB** detached BTF (`bpftool ... format raw` parses clean,
  335,645 lines). Surface structs present with **byte-exact** offsets vs the DWARF oracle
  (`pahole -C`): `ssl_extension` 0/2/4; `http_parse_ctx` incl. bitfields `state`@10, `reqresp`/`output_header`@13;
  `ssl_ctx` hn/cf/sp @8/16/24; `connflow` present. The two `_Atomic`-bearing structs (both **ours** —
  `ls_ring`, `ls_tp_seg`; TMM core uses no atomic members) are restored and byte-exact
  (`0 8 12 16 20 24 32 40 48` / `0 8 12 16 20 24 28`).
- *Open (Phase 4, not a gate blocker):* `bpftool btf dump format c` (the human `tmm.h`) FPEs on
  **C++ STL / Tcl** types in the debuginfo (`_Rb_tree_node_base`, `Tcl_Obj` — TMM embeds Tcl for iRules).
  The **binary BTF the loader consumes is unaffected**; `tmm.h` will be generated filtered to the C
  surface types (pahole per-type emits them fine). File a filtered-header generator in Phase 4.

**Phase 3 — relocator (the one substantial new component). — CORE MATH PASSED + INTEGRATED 2026-08-26.**
Read the program's `.BTF.ext` relocations, resolve against TMM's BTF, patch the offset immediates,
THEN verify + JIT. No libbpf/kernel runtime deps — just the relocation math. Will run on the prepare
thread (like the signature check; mind the no-malloc-on-foreign-TMM-threads rule).
*Falsifier:* relocated offsets must equal what our DWARF derivation says for the same fields — that
derivation is the oracle.

*Result (MEASURED, tool-witnessed — build box, TMM BTF from build 005835f9):* wrote a self-contained
relocator `substrate/ls_core_relo.c` (240 lines, no libbpf): parses BTF (local + target), skips
mods/typedefs, resolves `FIELD_BYTE_OFFSET` records by field NAME per access level, patches the insn
immediate; rejects every other relo kind loudly. Real emitted record shape confirmed
(`record_size=16`; one record per field read: `insn_off,type_id,access_str,kind`). **Falsifier test is
decisive:** a CO-RE program with a *deliberately wrong* local layout (`http_parse_ctx.pt`@8,
`data`@16) relocated against TMM's real BTF (116,755 types) to `pt`→**16**, `data`→**32** — byte-exact
vs the `pahole -C` oracle (`pt`@16, `data`@32) — and the instruction immediates flipped `8→16`,
`16→32`. 2 relos, 0 failed. Self-test travels with the file (`-DLS_CORE_RELO_TEST`); library-only
`gcc -c` compiles clean.
*Remaining (the review-gated step):* wire `core_field_offset` into `ls_vm.c:ls_vm_reload` before
`ubpf_load_elf_ex`; harden ELF/BTF bounds (untrusted-ish input in a security appliance); expose the
API via a small header (drops the static/unused warnings); confirm the prep thread's allocation
policy. This is the integration the reviewer wanted tightest — do it as its own reviewed change.

*Integration (MEASURED, build box, build 8f324a3480fa):* refactored `ls_core_relo.c` into a hardened library (`ls_core_relo.h`; single entry `ls_core_relocate`, all ELF/BTF/.BTF.ext offsets bounds-checked; self-test still PASSES rc=0 against the clean-build BTF). Wired into `ls_vm.c:ls_vm_arm` **before** `ubpf_load_elf_ex`, on the TMM thread (via `ls_prep_run_pending` -> `ls_vm_reload`, where malloc is legal). Target BTF loaded once via `ls_vm_target_btf()` (mmap of `/usr/share/ls/tmm.btf`, cached in `g_ls_btf` --- one whitelist entry). FAIL-DARK: no target BTF, or any unresolved record, refuses the load. `make tmm-gdb` EXIT=0; binary carries `ls_core_relocate`/`ls_core_btf_open`/`g_ls_btf`, bespoke still 0. BTF generated by patched pahole: `pahole --lang_exclude=c++ --btf_encode_detached` (atomic->volatile patch at `toolchain/pahole-atomic-qualifier.patch`).
*Remaining for live use:* bake `tmm.btf` (the build's own, stamped with its build id) into the image at `/usr/share/ls/tmm.btf` via `bnk-bake-tools.sh`; then a live arm+relocate on the cluster. Build-id match (loader verifies BTF vs `/proc/self/exe`) is a hardening follow-up.

**Phase 4 — one *surface* as portable CO-RE bytecode. — PASSED (off load path) 2026-08-26.**
Author a real surface with `preserve_access_index` field reads against real TMM structs — no bespoke
helper, no baked offset, no rebuild.
*Off-load-path falsifier (met):* real-struct CO-RE bytecode relocates to the running build's real
offsets (oracle) AND PREVAIL admits the relocated bytecode.
*Live falsifier (deferred to 3b + cluster):* it arms the hook, reads the real bytes, acts.

*Surface choice — ALPN reframed (honest):* the plan named ALPN, but TMM exposes ALPN only through its
extension parser (`ssl_ext_get_by_type`) — a **helper call**, i.e. the bespoke, build-coupled
anti-pattern this whole pivot rejects. So the first *pure* CO-RE surface is a field-read one:
`substrate/surfaces/http_observe.bpf.c`, per-request HTTP logic reading the parser's `state` and
`version_num` — the kind of mid-parse decision iRules can't express. ALPN is reclassified as a
**helper-class consumer** (its own decoupling track), not the first pure-CO-RE surface.

*Result (MEASURED, tool-witnessed — build box, pinned clang-18 + PREVAIL, TMM BTF build 005835f9):*
surface compiled portable with deliberately-wrong local offsets (`state`@0, `version_num`@2);
`ls_core_relo` relocated against TMM BTF to `state`→**10** (a byte-aligned bitfield — resolved
correctly) and `version_num`→**12**, byte-exact vs the `pahole -C` oracle (`state` 8:16=byte10,
`version_num`@12); instruction immediates flipped 0→10, 2→12. **PREVAIL PASS on both the unrelocated
and the relocated object** under `--termination --no-division-by-zero --strict` — so verify-after-
relocate is sound. 2 relos, 0 failed.

**Phase 5 — prove portability (the payoff).**
Run the IDENTICAL CO-RE bytecode against TWO TMM builds with different offsets, relocating against
each build's BTF at load.
*Falsifier:* if it needs recompiling per build, CO-RE isn't real. If it doesn't — "burns a build" is
dead, and the architecture is proven.

**Phase 6 — retire the anti-patterns.**
Deprecate typed ctx builders, bespoke accessors, baked offsets; migrate shields to CO-RE. Record the
build-coupled detour in CONTESTED-PREMISES.md.

## Role split
- **Architect (user):** Phase 0 (done), and a gate review at each phase boundary — especially the
  Phase 3 relocation math.
- **Me:** execute each bounded phase, verify on the pinned toolchain, bring a falsifiable result, and
  stop. No advancing a phase or inventing architecture between gates.

## Top risks (surfaced, not hidden)
- **PREVAIL + relocated CO-RE** (Phase 1) — make-or-break; de-risked first, off TMM.
- **Relocator port** (Phase 3) — the real work; bounded by libbpf's existing implementation, checked
  against our DWARF oracle.
- **DWARF→BTF cleanliness** (Phase 2) — *FIRED & RESOLVED 2026-08-25:* stock pahole died on `_Atomic`
  types; fixed with pahole v1.29 + a one-line atomic→volatile encoder patch (now a toolchain pin). See Phase 2.

---

## BTF as a build artifact (embedded in the binary — the kernel's model)

Resolved 2026-08-26, grounded in the cached kernel docs (SOURCES.md): the kernel embeds its BTF as a
`.BTF` ELF section in `vmlinux` (pahole at build) and only re-exposes it via `/sys/kernel/btf/vmlinux`
because userspace cannot read kernel memory. TMM is one userspace process, so its equivalent is to
read its **own** `.BTF` section from `/proc/self/exe` — the same model minus the sysfs indirection,
and the BTF cannot mismatch the binary because it *is* the binary's section.

- **Loader (DONE, validated):** `ls_vm_target_btf()` mmaps `/proc/self/exe`, `ls_core_btf_find_in_elf`
  locates the `.BTF` section (bounds-checked; skips NOBITS like `.bss` — a bug the round-trip test
  caught), `ls_core_btf_open` parses it. Round-trip proven on the build box: `objcopy` a `.BTF` onto
  the stripped runtime binary → the loader reads its own section (6.7 MB, 116,690 types) → relocates
  a surface **rc=0**.
- **Toolchain (DONE):** `substrate/toolchain/build-pahole.sh` builds the patched pahole reproducibly
  (dwarves v1.29 + the atomic→volatile patch), idempotent, to `~/.cache/ls-pahole`.
- **Packaging (PENDING — wire + validate with a real bake):** in `bnk-bake-tools.sh`, after the DEB
  extract, generate the BTF from the build's debuginfo and embed it into the runtime binary:
  ```
  PAHOLE=$(substrate/toolchain/build-pahole.sh)
  "$PAHOLE" --lang_exclude=c++ --btf_encode_detached="$CTX/tmm.btf" <extracted tmm64.no_pgo.debug>
  objcopy --add-section .BTF="$CTX/tmm.btf" --set-section-flags .BTF=readonly,data           "$RT/usr/bin/tmm64.no_pgo" "$CTX/tmm64.no_pgo"    # build box has binutils; image may not
  readelf -SW "$CTX/tmm64.no_pgo" | grep -q '\.BTF'        # verify before shipping
  ```
  then `Dockerfile.ls-tools` COPYs `$CTX/tmm64.no_pgo` over the image's binary. Left unwired here
  rather than committing an unvalidated edit to the working bake script; wire it when we run the
  bake for the first live arm.

## Assumptions about TMM's normal build (factored into the design)

The design is a standard `make tmm-gdb` plus our adjustments (substrate sources in `filelist`, the
globals-whitelist entries, the `-fpatchable-function-entry` pad flag, and the BTF-embed packaging
step). What it assumes about that build:

*Verified — safe to rely on:*
- **`objcopy --add-section .BTF` preserves the GNU build-id** (checked: 244673ff… identical before/
  after). So embedding BTF is invisible to the arming build-id gate; embed order vs hook-index
  stamping does not matter.
- **Struct layout is DWARF-exact and ABI-stable** across PGO/`-O` variants (relocator offsets matched
  the `pahole -C` oracle). BTF from one variant describes another's layout.

*Real dependencies the design is built around:*
1. **The build must emit DWARF** (`tmm-debuginfo`, via `make tmm-gdb`/`GDB_INCLUDE`). A stripped
   release build with no debug info yields no BTF → no CO-RE. CO-RE targets a debuginfo-emitting build.
2. **BTF, entry pads, and arming must all land on the SAME binary variant.** TMM ships several
   (`tmm64.no_pgo`, `tmm64.debug`, PGO). Arming needs the **padded** binary; the Dockerfile already
   repoints `/usr/bin/tmm` to it (the `tmm.debug`-has-no-pads bug shipped 4×). The `.BTF` must be
   embedded in *that* binary. Embedding in the binary (vs a loose file) makes this self-consistent:
   the BTF travels with whatever was armed.
3. **BTF generation is pinned-toolchain-sensitive.** pahole choked on `_Atomic` (patched) and C++
   reference types (`--lang_exclude=c++`). A clang/toolchain bump can surface new DWARF forms —
   re-validate BTF generation on any toolchain change, same discipline as PREVAIL/clang (rule 5).
4. **The embed runs on the build box, not in the image.** `objcopy`/binutils live on the build box; a
   data-plane container may not have them. Generate+embed in the bake; ship the embedded binary.
5. **We add a post-build step, not change F5's build.** BTF generation is our packaging step over the
   debuginfo; no F5 source or Makefile is touched.

*Risk to watch (not currently triggered):* **LTO / aggressive optimization could drop or merge
types.** The `no_pgo` debug build keeps all surface structs (verified present); revisit if a build
ever enables LTO.

## The 5-byte entry pad is still required (orthogonal to CO-RE)

Attaching and field-reading are separate mechanisms. `-fpatchable-function-entry=5,0` leaves a 5-byte
nop sled at every function entry so the trampoline can overwrite it with a `JMP rel32` (5 bytes) at
runtime — this is what makes "arm any function on a running TMM, no restart" possible, and it is the
core of the probe/debug value. CO-RE only resolves field offsets in the loaded bytecode; it does not
touch attachment. Retiring the bespoke ctx layer left `ls_tramp`/`ls_arm`/`ls_swap` intact and the
pads present in the binary (`__patchable_function_entries` section confirmed). Dropping the pad would
mean a different, worse attach mechanism (breakpoint/trap, or bpftime-style inline rewriting) — not
worth 5 nops per function, the standard kernel-ftrace approach.

## LIVE ARM — the first end-to-end surface (PASSED 2026-08-26)

*MEASURED, cluster-witnessed (datkube eob-bnk-datkube-01 / 10.145.40.193, pinned image build
ee2056234fd0 with embedded `.BTF`, stable pod, Gateway-API listener VIP 11.11.11.99):*

`probe_parser` (independently compiled → PREVAIL → signed; NOT baked) delivered over the loader
socket into a running TMM:
- **Signature verified** on the prepare thread; **`ls_vm: CO-RE relocated 1 field offset(s)`** — the
  loader read the binary's OWN embedded `.BTF` (`/proc/self/exe`) and resolved `http_parse_ctx.version_num`
  live; **`ARMED LIVE entry=0xccc604 slot=0 (no restart)`**, JIT on.
- **Fires once per request:** 40 requests → `fired=40`; +20 → +20 (exact hook fidelity).
- **Field read works live:** `errors=0` across 60 fires (a wrong/unreadable offset would fault
  probe_read and increment errors).
- **Disarm live:** `DISARMED LIVE`; +20 requests → +0 fired (frozen); traffic 200 throughout.

This closes the whole architecture on a running BIG-IP: attach to an internal function with no iRule
event, read its internal field via CO-RE against the binary's own type info, arm/disarm on live
traffic with no restart — and the bytecode was compiled/verified/signed as a completely independent
process and loaded over the socket. Two-step load then arm: `ls-load.py load <slot> <prog> <mode>`
puts the (relocated, verified, JIT'd) program in the slot; `ls-load.py arm <slot> <hook>` patches the
function entry. Per-call cost NOT claimed here (the `cycles` counter is preemption-dominated — probe #5).

## Loose ends closed (2026-08-26)

- **#1 negative test** — `substrate/shields/reject_memory.bpf.c` (generic-ctx, dereferences a raw
  `arg[0]`): PREVAIL refuses it (verdict FAIL). Restores the verifier self-check the typed `reject_*`
  removal lost.
- **#4 live** — **re-point** proven (`ls_vm: RELOADED slot=0`: probe→shield swapped in one slot,
  no restart) and **trace end-to-end** proven (`trace_stream` armed → `ls_drain --segment` streamed
  one JSON record per request). Honest finding: at an `fentry` hook the read fields are 0 because the
  hook fires at function *entry*, before `http_parse_client_headers` populates `state`/`version_num`
  (`arg[0]` IS `http_parse_ctx *`, confirmed in `signatures.tsv`); a probe wanting parsed values
  attaches at the exit or a downstream function.
- **#3 loader ergonomics** — MEASURED live (build `80aff243`): the loader now takes the entry
  function FROM the object (`ls_function_in_section`) instead of the fixed `shield`. A program named
  `probe_parser` loads and the log shows `function=probe_parser` derived — the same program was
  *refused* by the old loader (`'shield' does not live in section`).
- **#2 armed cost floor** — MEASURED live: added `cycles_min` to the per-slot timing. Over 80 fires:
  `cycles_min=1484`, mean ≈ 15k, `cycles_max=578370` — the mean/max are preemption-dominated (our
  recorded caveat), so **1484 cycles (≈ 570 ns @ 2.6 GHz) is the floor**. Scope: the rdtsc pair
  brackets the VM exec + the range-checked `probe_read` helper inside `ls_vm_call`; it excludes the
  trampoline register save/restore. **Probe #5 5b RESOLVED 2026-08-26:** rather than risk rdtsc in the
  live trampoline asm (a bug there crashes every armed request), the exact wrapper sequence
  (`9 pushq + call/ret + 9 popq`) was microbenched in isolation with the same rdtsc min method ---
  it comes in **below the rdtsc measurement floor** (< 24 cycles, ~0 after subtracting the instrument):
  register ops on the L1 stack overlap out-of-order. So the trampoline wrapper adds nothing measurable,
  and **the full armed-path floor ~= 1484 cycles (~570 ns @ 2.6 GHz)** --- dominated by the VM exec and
  the range-checked `probe_read`, not the attach mechanism.

## Surface test matrix (surfaces not shields)

Four surfaces the substrate serves — **shield · probe · trace · debug** — each with tests that
exercise it. Readiness: **▶** provable off the load path today (compile → relocate → PREVAIL, plus
the two-build portability check) · **⧗** needs the build's BTF baked into the image + a cluster arm ·
**⚠** additionally gates on the threat-model analysis (TMA). *No performance claim is a claim until
measured on the pinned build + a stable pod (rule 5); report distributions, not means — the counter
mean is dominated by preemption artifacts.*

Attach points/fields below are real — present in the build BTF (`http_parse_ctx`, `ssl_ctx`,
`connflow`); `http_parse_client_headers` is proven to fire once per request.

### probe — attach where no iRule can, read internal state, count/sample/measure
1. **Count-by-internal-field** ▶⧗ — read `http_parse_ctx.version_num`, bucket per request. *Pass iff* bucket deltas equal driven traffic.
2. **Hook fidelity** ⧗ — fires exactly once per request across N. *Pass iff* fired-delta == request count.
3. **Bitfield read** ▶ — read `http_parse_ctx.state` (byte-aligned bitfield → byte 10). *Pass iff* value matches; a sub-byte bitfield is rejected, not mis-read.
4. **Arm/disarm live** ⧗ — counts rise armed, freeze disarmed, no restart.
5. **Armed-hook overhead** — the one that needs a measurement, in two honest parts:
   - **5a external A/B** ▶⧗ (bytecode-only, aggregate bound): arm a **no-op probe**; steady traffic
     (fixed RPS, connection reuse, stable pod, pinned build); per-request latency **distribution**
     (p50/p90/p99) + throughput, **disarmed vs armed**, A/B-alternated to cancel drift, ≥100k
     req/state. Report the **delta distribution**. *Honest limit:* bounds the cost (≤ X µs/req); a
     single hook's ns cost sits below request-latency noise, so 5a cannot pin per-call ns.
   - **5b in-trampoline rdtsc** ⧗ (**the single structural change** — an rdtsc pair around the VM
     dispatch in `ls_tramp.c`, our own code, accumulating per-core {count,sum,min,max} read out via
     the ring/audit): per-invocation cycles for **trampoline dispatch + VM**, isolated from traffic
     noise. Report **min + histogram** (min = least preemption), convert to ns at the known clock,
     **subtract the empty rdtsc-pair cost** (as the bench already does). *Excludes* i-cache warm
     effects under real traffic — state it.

### trace — stream internal events off-box, live (via the ring + ls_drain)
1. **One-record-per-event** ⧗ — N requests → exactly N records, fields correct.
2. **Accounted overflow** ⧗ — drive faster than drain → dropped records increment a **drop counter**, never silently lost.
3. **Field-fidelity cross-check** ⧗ — streamed values match probe #1's counts.
4. **Multi-field record** ▶⧗ — emit ≥2 fields; drained layout matches the declared schema.

### debug — ad-hoc introspection, re-pointable, no rebuild/restart
1. **Named-field dump** ⧗ — operator names a field at demo time; live value matches an independent read.
2. **Re-point without restart** ⧗ — load bytecode A (field X), then B (field Y) into the same slot; both work, zero rebuild.
3. **Arbitrary attach** ▶⧗ — attach to a function with **no iRule event**; it arms and reads.
4. **Portability** ▶ — same debug bytecode vs **two builds** with different offsets; both read the right field (CO-RE payoff; shown for `http_observe`).

### shield — a verdict changes execution (enforcement; the CVE story, held last)
1. **Verdict gates the body** ⧗⚠ — condition true → `SAFE_RETURN` → body skipped (a probe on the body confirms zero entries); false → fall through.
2. **Fail-dark on bad load** ▶ — a program that fails relocation/verify is **refused**, never partially armed.
3. **Monitor vs enforce** ⧗⚠ — MONITOR records but doesn't gate; ENFORCE gates; mode-ceiling honored.
4. **Disarm restores original** ⧗⚠ — arm then disarm; original behavior returns, no residual, no restart.

### Bytecode-only vs structural change
- **Application timing** (durations between internal events, via `bpf_ktime_get_ns` id 5 + maps): **bytecode-only, precise, no TMM change.**
- **Mechanism's own per-call overhead:** **not** measurable precisely from bytecode (the program runs
  after the trampoline already paid its cost; `ktime` can't resolve ~10 ns). Precise measurement needs
  **5b's rdtsc pair in `ls_tramp.c`** — the single structural change, in code we own, not F5 source.
- **"iRules can't" for probe/trace/debug demo claims** still depends on the iRules-boundary
  verification (in progress) — the *tests* assert substrate behavior and need no iRules; the
  *comparison narrative* needs the cited boundary.

## Next structural extension — function EXIT (`fexit`) — ROADMAP

Today a hook attaches only at a function **entry**. Reading a function's *result* or its
post-execution state — and timing a single function's own duration — needs an **exit** hook. This
is a **structural change** (trampoline + a small ctx-ABI bump), tier **ROADMAP**: designed, not
built. It is the highest-leverage extension because it turns "read state before a function runs"
into "measure and act on what it did" — and it directly answers the `fentry`-timing limitation the
trace surface hit (fields read `0` at entry because the parser has not populated them yet).

**Mechanism — return-address hijack (no exit pad exists).** `-fpatchable-function-entry` gives a
pad at *entry* only; a `ret` is one byte with no room to patch, so exit is done the way the kernel's
`fexit`, frida, and bpftime all do it — hijack the return address, from the entry trampoline we
already have. At entry the stack is `[rsp]=body-return` (pushed by the pad's `call trampoline`),
`[rsp+8]=caller-return` (pushed by the caller). The trampoline overwrites `[rsp+8]` with an **exit
stub** and saves the real caller-return (plus the entry args) on a **per-core shadow stack**; the
body runs, its `ret` lands in the stub; the stub reads `rax` (the return value), pops the shadow
frame, runs the VM with an exit context, restores `rax`, and jumps to the real caller. LIFO handles
nesting/recursion.

**Checklist.** (1) a `(kind, slot)` dispatch split — a hook carries entry-vs-exit, arming an exit
hook still patches the *entry* pad but dispatches differently; (2) a per-core shadow stack, bounded
depth, overflow → fall through (never crash); (3) the asm exit stub + the `[rsp+8]` swap in
`ls_tramp_asm.c` / `trampoline_x86_64.S` (kept mirrored); (4) an exit ctx shape — the generic ctx
gains the **return value** (+ saved entry args): a `ctx_abi` version bump (already versioned); (5) a
`fexit/<fn>` program type PREVAIL admits. Everything else — the VM, ctx assembly, `ls_vm_call`,
CO-RE relocation, arming-by-name, signing, the ring — is unchanged.

**The gate (see P8).** A non-local exit (`setjmp`/`longjmp`) skips the body's `ret`, so the shadow
stack desyncs and the next exit jumps somewhere wrong. **Whether TMM uses `longjmp` on any path
under a hookable function decides feasibility** — and the P8 survey (2026-08-26, build box) settled it
**CLEAR**: TMM dynamically links glibc and imports no `longjmp`/`setjmp` and no C++ unwind machinery
(`_Unwind_*`/`__cxa_*`), so no non-local exit can bypass a hooked frame's `ret`. The pre-registered
falsifier survived. Tail calls and
shadow-stack depth are secondary guards.
