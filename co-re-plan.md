# CO-RE for TMM — the plan to portable, build-decoupled shields

**The target.** A shield is portable bytecode: it references TMM fields by *name*, carries CO-RE
relocation records, and the loader resolves offsets against **TMM's own type info at load time**.
TMM ships a fixed, general VM surface baked once (probe_read, maps, clock, trampoline). After that:
new capability = new bytecode, **zero TMM builds, zero bespoke C**, and the *same* shield runs across
TMM builds. This is the kernel CO-RE model, sourced from TMM instead of the kernel.

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

**Phase 1 — de-risk the chain OFF TMM (no TMM exposure).**
A toy C struct; a BPF program using `BPF_CORE_READ`; BTF via pahole; apply CO-RE relocations
(libbpf/bpftool); feed the RELOCATED program to PREVAIL; run on ubpf.
*Falsifier:* PREVAIL rejects relocated CO-RE bytecode, or ubpf can't run it → the approach is wrong,
learned in an afternoon at zero TMM risk. **The single make-or-break gate.**

**Phase 2 — TMM's BTF.**
`pahole -J` on TMM's debuginfo → BTF; dump → `tmm.h`. Verify it carries `ssl_ctx`,
`http_parse_info`, `ssl_extension`. Cross-check a few offsets against our existing DWARF derivation.
*Falsifier:* DWARF→BTF fails or key types absent.

**Phase 3 — relocator in the loader (the one substantial new component).**
Port libbpf's `bpf_core_apply_relo` into ls_vm_load.c: read the program's `.BTF.ext` relocations,
resolve against TMM's BTF, patch the offset immediates, THEN verify + JIT. No libbpf/kernel runtime
deps — just the relocation math. Runs on the prepare thread (like the signature check; no malloc on
foreign TMM threads).
*Falsifier:* relocated offsets must equal what our DWARF derivation says for the same fields — that
derivation becomes the oracle.

**Phase 4 — one shield as portable CO-RE bytecode.**
Rewrite ALPN with `BPF_CORE_READ` against `tmm.h` — no bespoke helper, no baked offset. Load via the
CO-RE path onto the EXISTING image (no TMM rebuild).
*Falsifier:* it arms ssl_alpn_match, reads the real ALPN bytes, acts.

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
- **DWARF→BTF cleanliness** (Phase 2) — TMM's DWARF is large and old-toolchain; pahole may need coaxing.
