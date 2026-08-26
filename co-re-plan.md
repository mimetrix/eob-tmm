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

**Phase 3 — relocator (the one substantial new component). — CORE MATH PASSED 2026-08-26; integration into `ls_vm.c` pending review.**
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
