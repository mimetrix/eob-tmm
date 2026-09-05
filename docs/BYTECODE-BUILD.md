# Bytecode build — the independent surface pipeline

How a **surface** (portable eBPF bytecode) is authored, compiled, verified, signed, and loaded into
a running TMM. This is a **completely independent process**: it never touches the TMM build, and the
same signed bytecode runs on **any matching build** because its field offsets are resolved at load
against that build's own type information. Building the TMM image is separate — see
[`TMM-BUILD.md`](TMM-BUILD.md).

> **The contract:** compile once, run on any matching build, no rebuild. A surface names TMM fields
> by name and carries relocation records; the loader rewrites the offsets against the running
> binary's embedded `.BTF` at load time. Validated end to end (live arm on the datkube cluster,
> 2026-08-26 — see `co-re-plan.md`).

## The model

Every surface is bytecode over the **generic register context** — the same context TMM's trampoline
hands every program:

```c
struct ls_ctx_generic { __u64 arg[5]; };   // arg[0..4] = the hooked function's rdi..r8
```

It reads TMM's internal state by **naming fields**, not by baked offsets. A minimal *relocatable*
view of a TMM struct is declared with `preserve_access_index`; only the field names must match TMM's
— the local offsets are irrelevant, the loader replaces them:

```c
struct http_parse_ctx { __u8 state; __u8 version_num; } __attribute__((preserve_access_index));
```

A verified program cannot chase a raw pointer, so fields are read with `bpf_probe_read(&h->field)` —
which compiles to an address computation with the offset as an **immediate**, and that immediate is
what the loader patches (see [Conventions](#conventions)).

## The four surfaces

`substrate/surfaces/` (see its `README.md`), one per surface kind:

| file | surface | attach (section) | reads | does |
|---|---|---|---|---|
| `probe_parser.bpf.c` | **probe** | `fentry/http_parse_client_headers` | `http_parse_ctx.version_num` | return a bucket the host counts |
| `debug_field.bpf.c` | **debug** | `fentry/ssl_alpn_match` | `ssl_ctx.cf` (a *different* struct) | return one named field's live value |
| `shield_nullguard.bpf.c` | **shield** | `fentry/http_parse_client_headers` | `http_parse_ctx.parser` | `SAFE_RETURN` if NULL (skip the body) |
| `trace_stream.bpf.c` | **trace** | `fentry/http_parse_client_headers` | `version_num`+`state` | emit a record to the ring (id 25 → `ls_drain`) |

## The pipeline

```
author ──▶ clang -target bpf ──▶ PREVAIL ──▶ sign_shield.py ──▶ deliver ──▶ ls-load.py load ──▶ ls-load.py arm
 name       .bpf.o (+.BTF,        verify      .bpf.sig          to the pod   relocate+verify+     patch the
 fields     .BTF.ext relocs)      (pinned)    (signed binding)               JIT into a slot      function entry
```

Steps 2–4 are done for every surface by **`bnk-build-programs.sh`** (which cleans its output dir and
covers both `shields/` and `surfaces/`); the sections below are what it does per program.

### 1 · Author
Write `surface.bpf.c`: generic ctx, minimal `preserve_access_index` structs naming the fields you
need, read with `bpf_probe_read`, entry function named **`shield`**, section **`fentry/<hook>`**. For
field names, author against the build's `tmm.h` (the dump of TMM's BTF — the `vmlinux.h` equivalent).

### 2 · Compile (independent of the TMM build)
```bash
clang -O2 -g -target bpf -I substrate -c surface.bpf.c -o surface.bpf.o
```
Produces `.BTF` (the program's local types) and `.BTF.ext` (CO-RE relocation records: one
`{insn_off, type_id, access_str, kind}` per field access — the same format the kernel documents).

### 3 · Verify (pinned toolchain)
```bash
prevail surface.bpf.o fentry/<hook> --termination --no-division-by-zero --strict --stack-size 256
```
PREVAIL must PASS. The **section name selects the program type** and the context descriptor PREVAIL
verifies against — it must be `fentry/<hook>`. Run on the pinned clang-18 + vendored PREVAIL (rule 5:
a different clang can flip the verdict).

### 4 · Sign
```bash
python3 substrate/sign_shield.py --key <sk> --prog surface.bpf.o \
        --hook <hook> --mode-ceiling monitor -o surface.bpf.sig
```
The signature vouches for **this exact program at this exact hook**, with a mode ceiling (monitor /
enforce) and an optional build-id range, in a signed *binding*. The `.sig` travels beside the `.o`
(`surface.bpf.o` → `surface.bpf.sig`). The image's loader trusts the corresponding public key
(checked at bake time); an unsigned or wrong-key program is refused at load.

### 5 · Deliver + load + arm
The signed `.bpf.o` + `.sig` are the independent artifacts. Get them to where `ls-load.py` (baked in
the pod) can read them, then **load** and **arm** — two distinct steps:
```bash
# deliver the runtime payload (not baked into the image)
kubectl cp surface.bpf.o  <pod>:/tmp/ -c f5-tmm
kubectl cp surface.bpf.sig <pod>:/tmp/ -c f5-tmm

# LOAD: relocate against the running binary's .BTF, verify signature, PREVAIL is already done,
#       JIT into a slot. mode is numeric: 0=disable 1=monitor 2=enforce (≤ the signed ceiling).
kubectl exec <pod> -c f5-tmm -- python3 /usr/bin/ls-load.py load 0 /tmp/surface.bpf.o 1
#   → ls_vm: CO-RE relocated N field offset(s)   ← the loader read /proc/self/exe's .BTF
#   → OK loaded slot=0 mode=1 signature=verified

# ARM: patch the function entry (the 5-byte pad → JMP to the trampoline). Live, no restart.
kubectl exec <pod> -c f5-tmm -- python3 /usr/bin/ls-load.py arm 0 http_parse_client_headers
#   → OK ARMED LIVE entry=0x… slot=0 (no restart)
```
The **hook comes from the signed binding**, not from an argument — a key asserted it. `load` puts the
relocated, verified, JIT'd program in the slot; `arm` makes the function actually reach it.

### Observe / remove
```bash
ls-load.py status  0                       # armed, fired, safe_returns, errors, cycles
ls-load.py disarm  http_parse_client_headers   # restore the entry, live; the counter freezes
ls_drain                                   # (trace surfaces) read the ring → JSON records
```

## Why this is build-decoupled

The only thing a surface needs from a TMM build is **field names** (for authoring) — and the actual
offsets are resolved **at load, not at compile**, by the loader's CO-RE relocator against the running
binary's embedded `.BTF`. So:

- **CHANGED 2026-09-05 — offsets are now resolved at SIGN time, not at load.** The paragraph that
  stood here said the same signed `.bpf.o` runs on any build whose structs still contain those
  fields, because the loader relocated against the binary's embedded `.BTF`. That was true and was
  given up deliberately: resolving offsets in the pipeline is what lets the shipped binary carry
  **no type information at all** — 0 bytes of `.BTF` where it held 6,711,805
  (`02-RESEARCH-PARAMETERS.md` P9).
- So a program is now **signed for one build** (`build_min == build_max`) and must be re-signed for
  the next. The loader **refuses** it otherwise, and refuses a program that still carries
  `.BTF.ext` with the cause on the log — a wrong-build load fails loudly instead of reading
  placeholder offsets. Measured: `bnk-test-build-gate.sh` 9/9, `bnk-test-btfless.sh` 6/6.
- What did **not** change: nothing about compiling a surface depends on rebuilding TMM.
- Nothing about compiling a surface depends on rebuilding TMM. A new attach point or a new field read
  is a **new program in minutes**, not a build cycle.

## Conventions (or the load is refused)

- **Entry function is `shield`.** TMM's loader (finding O14) selects the program function by name and
  defaults to `shield`; a differently-named entry is refused (`'shield' does not live in section …`).
- **Section is `fentry/<hook>`.** It selects the PREVAIL program type *and* names the attach point.
- **Field names must match TMM's** (the loader matches by name against the target BTF). A name absent
  in the target fails the relocation and the load is refused (fail-dark) — never mis-relocated.
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
| `substrate/ls_core_relo.c` | (load-time, in TMM) | the relocator: patch field offsets against the binary's `.BTF` |
| `ls_drain` | observe | read the egress ring (trace surfaces) → JSON |

Not claimed here: **per-call cost.** The `status` `cycles` counter is preemption-dominated; a
defensible number needs the A/B and in-trampoline-rdtsc methodology of probe #5 (`co-re-plan.md`).
