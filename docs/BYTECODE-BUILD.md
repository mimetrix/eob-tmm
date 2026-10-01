# Bytecode build — the independent surface pipeline

For the complete ordering from a TMM source-tree path, start with
[BUILD-FROM-SOURCE.md](BUILD-FROM-SOURCE.md). It names the required external
inputs and the gaps that prevent a fresh-host build of the current sources.

How a **surface** (portable eBPF bytecode) is authored, compiled, verified, signed, and loaded into
a running TMM. It does not require rebuilding TMM, but consumes that build's **packaged
runtime/debug pair and build-side metadata**. Offsets and the attachment target are resolved
before final verification/signing. Building the TMM image is separate — see
[`TMM-BUILD.md`](TMM-BUILD.md).

> **Current contract, 2026-09-24:** author by field/function name on the build box; deliver a
> relocated, verified, signed program for **one full GNU build ID**. No gateway discovery/type
> catalog is needed. The earlier load-time relocation contract was superseded on September 4;
> authenticated target binding now also constrains ARM. See
> [`catalog-free-deployment.md`](../catalog-free-deployment.md) for measured scope and limits.

**New users:** start with [`EBPF-TUTORIAL.md`](EBPF-TUTORIAL.md) and
[`substrate/template.c`](../substrate/template.c). That example combines the
current helper interfaces with configuration input and event output.

## The model

Every surface is bytecode over the **generic register context** — the same context TMM's trampoline
hands every program:

```c
struct ls_ctx_generic { __u64 arg[5]; };   // first 40 bytes of the 96-byte entry context
```

It reads TMM's internal state by **naming fields**, not by baked offsets. A minimal *relocatable*
view of a TMM struct is declared with `preserve_access_index`; only the field names must match TMM's
— the local offsets are placeholders, the build-side relocator replaces them:

```c
struct http_parse_ctx { __u8 state; __u8 version_num; } __attribute__((preserve_access_index));
```

A verified program cannot chase a raw pointer, so fields are read with `bpf_probe_read(&h->field)` —
which compiles to an address computation with the offset as an **immediate**, and that immediate is
what the relocator patches (see [Conventions](#conventions)). Entry/exit contexts are 96 bytes;
exit return value is at byte 40. See `../ctx-contract-validation.md`.

## The four surfaces

`substrate/surfaces/` (see its `README.md`), one per surface kind:

| file | surface | attach (section) | reads | does |
|---|---|---|---|---|
| `probe_parser.bpf.c` | **probe** | `fentry/http_parse_client_headers` | `http_parse_ctx.version_num` | return a bucket the host counts |
| `debug_field.bpf.c` | **debug** | `fentry/ssl_alpn_match` | `ssl_ctx.cf` (a *different* struct) | return one named field's live value |
| `shield_nullguard.bpf.c` | **shield** | `fentry/http_parse_client_headers` | `http_parse_ctx.parser` | `SAFE_RETURN` if NULL (skip the body) |
| `trace_stream.bpf.c` | **trace** | `fentry/http_parse_client_headers` | `version_num`+`state` | emit a record to the ring (id 25 → `ls_drain`) |

## The pipeline

| Zone | Steps | Artifact / effect |
|---|---|---|
| Build box | Author → clang-18 → field relocation → strip BTF → `bind_target.py` | Final `.bpf.o` with `.ls.target`, no unresolved fields |
| Build box | PREVAIL final bytes → `sign_shield.py` | Signed binding/hash covering the full target record |
| Gateway control path | Deliver → LOAD → ARM | Authenticate build/target/kind/ceiling, JIT, patch admitted entry |
| Gateway data path | Trampoline → JIT | Evaluate the program; no catalog lookup |

Steps 2–4 are done for every surface by **`bnk-build-programs.sh`** (which cleans its output dir and
covers both `shields/` and `surfaces/`); the sections below are what it does per program.

### 1 · Author
Write `surface.bpf.c`: generic ctx, minimal `preserve_access_index` structs naming the fields you
need, read with `bpf_probe_read`, entry function named **`shield`**, section **`fentry/<hook>`**. For
field names, author against the build's `tmm.h` (the dump of TMM's BTF — the `vmlinux.h` equivalent).

### 2 · Compile (independent of the TMM build)
```bash
clang-18 -O2 -g -target bpf -I substrate -c surface.bpf.c -o surface.bpf.o
```
Produces `.BTF` (the program's local types) and `.BTF.ext` (CO-RE relocation records: one
`{insn_off, type_id, access_str, kind}` per field access — the same format the kernel documents).

### 3 · Resolve, bind, then verify (pinned toolchain)

Use `bnk-build-programs.sh` or `tmmtrace-buildbox.sh` to relocate against the current
`tmm.btf`, remove `.BTF`/`.BTF.ext`, and run `substrate/bind_target.py` against the matching
packaged runtime/debug pair and hook index. The binder rejects ambiguous/unpadded entries;
exit hooks also require return-ABI and unwind admission. Then verify the **final object**:
```bash
prevail surface.bpf.o fentry/<hook> --termination --no-division-by-zero --strict --stack-size 256
```
PREVAIL must PASS. The **section name selects the program type** and the context descriptor PREVAIL
verifies against — use `fentry/<hook>` or `fexit/<hook>`. Run on pinned clang-18 + vendored PREVAIL (rule 5:
a different clang can flip the verdict).

### 4 · Sign
```bash
python3 substrate/sign_shield.py --key <sk> --prog surface.bpf.o \
        --hook <hook> --mode-ceiling monitor \
        --build-min 0x<first-eight-build-id-digits> --build-max 0x<same-digits> -o surface.bpf.sig
```
The signature vouches for **this exact program at this exact hook**, with a mode ceiling (monitor /
enforce) and exact build prefix in a signed *binding*. The authenticated `.ls.target` additionally
requires the **full** build ID. The `.sig` travels beside the `.o`
(`surface.bpf.o` → `surface.bpf.sig`). The image's loader trusts the corresponding public key
(checked at bake time); an unsigned or wrong-key program is refused at load.

### 5 · Deliver + load + arm
The signed `.bpf.o` + `.sig` are the independent artifacts. Get them to where `ls-load.py` (baked in
the pod) can read them, then **load** and **arm** — two distinct steps:
```bash
# deliver the runtime payload (not baked into the image)
kubectl cp surface.bpf.o  <pod>:/tmp/ -c f5-tmm
kubectl cp surface.bpf.sig <pod>:/tmp/ -c f5-tmm

# LOAD: verify signature/hash and target/build/kind/ceiling, then JIT. PREVAIL is already done.
# mode is numeric: 0=disable 1=monitor 2=enforce (≤ the signed ceiling).
kubectl exec <pod> -c f5-tmm -- python3 /usr/bin/ls-load.py load 0 /tmp/surface.bpf.o 1
#   → OK loaded slot=0 mode=1 signature=verified

# ARM: patch the function entry (the 5-byte pad → CALL to the trampoline). Live, no restart.
kubectl exec <pod> -c f5-tmm -- python3 /usr/bin/ls-load.py arm 0
#   → OK ARMED LIVE entry=0x… slot=0 (no restart)
```
The **hook comes from the signed binding**, not from an argument — a key asserted it. `load` puts the
relocated, verified, JIT'd program in the slot; `arm` makes the function actually reach it.
An optional ARM name/address must match the signed target. Disarm before changing target/kind;
same-target replacement while attached is supported, subject to existing reclamation limits.

### Observe / remove
```bash
ls-load.py status  0                       # armed, fired, safe_returns, errors, cycles
ls-load.py disarm  http_parse_client_headers   # restore the entry, live; the counter freezes
ls_drain                                   # (trace surfaces) read the ring → JSON records
```

## Why this is build-decoupled

The surface pipeline consumes build artifacts but does not modify or rebuild TMM:

- **CHANGED 2026-09-05 — offsets are now resolved at SIGN time, not at load.** The paragraph that
  stood here said the same signed `.bpf.o` runs on any build whose structs still contain those
  fields, because the loader relocated against the binary's embedded `.BTF`. That was true and was
  given up deliberately: resolving offsets in the pipeline is what lets the shipped binary carry
   **no embedded BTF** — 0 bytes of `.BTF` where it held 6,711,805
  (`02-RESEARCH-PARAMETERS.md` P9).
- So a program is now **signed for one build** (`build_min == build_max`) and must be re-signed for
  the next. The loader **refuses** it otherwise, and refuses a program that still carries
  `.BTF.ext` with the cause on the log — a wrong-build load fails loudly instead of reading
  placeholder offsets. Measured: `bnk-test-build-gate.sh` 9/9, `bnk-test-btfless.sh` 6/6.
- **2026-09-24:** gateway TSV/JSON catalogs are also removed, and `.ls.target` binds one full
  build ID, entry and kind. This is metadata removal, not symbol concealment.
- Nothing about compiling a surface depends on rebuilding TMM. A new attach point or a new field read
  is a **new program in minutes**, not a build cycle.

## Conventions (or the load is refused)

- **One entry function in the tracing section.** The loader selects its function symbol and checks
  section membership (finding O14); `shield` is conventional, generated names are supported.
- **Section is `fentry/<hook>` or `fexit/<hook>`.** It selects PREVAIL's context and names the hook.
- **Field names must match TMM's** (the build-side relocator matches against target BTF). A name
  absent in the target fails relocation before signing.
- **Read via `bpf_probe_read(&struct->field)`**, not a direct `struct->field` load. A verified program
  can't chase the pointer, and the address-of form compiles to an ALU add with the offset as an
  **immediate** — which is the form the relocator patches. (Direct `LDX` loads patch an instruction's
  *offset field*, which the relocator does not handle — and PREVAIL forbids that access anyway.)
- **Byte-aligned fields only.** A sub-byte bitfield has no byte offset; the relocator rejects it.

## Tools

| tool | step | what it does |
|---|---|---|
| `clang -target bpf` | 2 | compile to eBPF with `.BTF`/`.BTF.ext` CO-RE records |
| `ebpf-verifier/bin/prevail` | 3 | static verification (termination, memory safety, bounded) |
| `substrate/sign_shield.py` | 4 | sign the binding (hook, mode ceiling, build range) → `.bpf.sig` |
| `bnk-build-programs.sh` | 2–4 | do all three for `shields/` + `surfaces/`, cleaning its output dir |
| `env/scripts/ls-load.py` | 5 | speak the loader socket: `load` / `arm` / `status` / `disarm` |
| `substrate/ls_core_relo.c` | 3, build box | patch field offsets against detached target BTF |
| `substrate/bind_target.py` | 3, build box | resolve and bind full build ID + padded entry + kind |
| `ls_drain` | observe | read the egress ring (trace surfaces) → JSON |

Not claimed here: **per-call cost.** The `status` `cycles` counter is preemption-dominated; a
defensible number needs the A/B and in-trampoline-rdtsc methodology of probe #5 (`co-re-plan.md`).
