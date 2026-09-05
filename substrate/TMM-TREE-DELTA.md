# What changes in the TMM tree

This repo holds the substrate **sources**; they are compiled into TMM **elsewhere**, in the TMM
build tree. That split is the reason someone can read every file here and still not be able to
rebuild what ran. This file is the missing half: the complete, exact delta applied to the TMM tree.

**The headline property — and read the scope carefully, because it depends on tree state.** In the
**substrate-only** tree (no vulnerable-SSL overlay) the substrate adds **36 files and ~8,400 lines**
into `src/base/` (33) and `src/compile/` (2 whitelist config), edits three build-configuration files
(`filelist` and the two globals whitelists), and adds a `Makefile.overrides` — verified 2026-08-31 by
`git status --porcelain src/` on the build box. The larger **46 files / ~7,800 lines** figure counts a
tree that **also** has the vulnerable-SSL demo overlay under `src/modules/hudfilter/ssl/` plus the
`ssl.c` revert (`VULNERABLE-BUILD.md`), which is not applied in the current tree. **No existing F5
function BODY is edited **by the substrate.** The tree as it stands also carries the **CVE-2025-41414 revert** in `http2.c`, which *does* edit an F5 function body — a demonstration artifact rather than integration, and unrecorded until 2026-09-04 (`CONTESTED-PREMISES.md` §16)** --- that is the accurate form of
the claim, and it is smaller than "modifies no F5 source file", which this file used to say: nothing
is spliced into TMM's own logic, because startup registers through the `INIT_FUNC` linker set. That
constraint is real and load-bearing, because the shield targets a TMM that is *already running*.

The **tracepoint** (§6b) does edit two F5 source files, deliberately, because a tracepoint is a
build-time decision about what TMM should expose and a call site is the correct mechanism for one.
So `git status` in the TMM tree should show `M` on exactly five files — three build-config, plus
`http.c` and `http1x.c`. **Any other `M` is a regression.**

Tree: `gitswarm.f5net.com/tmm/tmm` (MBIP), version `10.207.3-main.bdbfc7e182`, built with
`make tmm-gdb`. Paths below are relative to `src/`.

---

## 1. New source files — by function (current tree, verified 2026-08-31)

Authoritative source: `git status --porcelain src/` on the build box, **re-measured 2026-09-05:
36 added, 4 modified**. The tree adds **36 files** (34 under `src/base/`, 2 whitelist snapshots under
`src/compile/`) and edits **4** F5 files —
corrected 2026-09-04 from **3**. The three build-configuration edits below are the substrate's own;
the fourth is `src/modules/hudfilter/http2/http2.c`, carrying the **CVE-2025-41414 fix `81d3428d3d`
reverted** (`cve-41414-demonstration.md`). It was in no manifest, and it means **every binary built
from this tree is vulnerable to CVE-2025-41414 whatever it was built for**. Status only here, never
the diff. See `CONTESTED-PREMISES.md` §16 for why it stayed invisible. Of the
33 `base/` files, **13 `.c` are compiled into `tmm`** (they appear in `filelist` — §2); the rest are
headers pulled in by those, one build-box-only harness, and one data blob. Grouped by what they do:

| function | files (`base/`) | in `tmm`? |
|---|---|---|
| **VM / bytecode engine** — embed uBPF, load the ELF, JIT, the env knobs, per-core stack | `ls_vm.c` `ls_vm.h` · `ls_vm_load.c` · `ls_vm_config.c` `ls_vm_config.h` · `vm_stack_policy.h` | yes (`.c`) |
| **Build gate** — refuse a program signed for a different build | `ls_build_gate.h` | yes |
| **CO-RE relocation** — rewrite a program's field offsets to this build's layout | `ls_core_relo.c` `ls_core_relo.h` | yes |
| **Arm / trampoline** — patch & restore the 5-byte entry pad; build `ctx`, apply the verdict; INIT_FUNC startup | `ls_arm.c` `ls_arm.h` · `ls_prep.c` · `ls_tramp.c` · `ls_tramp_asm.c` (from `trampoline_x86_64.S`) | yes (`.c`) |
| **Function-exit hooks** — return-hijack + per-instance shadow stack | `ls_fexit.c` `ls_fexit.h` | yes |
| **Evidence ring** — shared-memory egress off the poll loop + event schemas | `ls_tp_emit.c` · `ls_tp.h` `ls_tp_ring.h` `ls_ring.h` `ls_tp_http.h` `ls_tp_shield.h` | yes (`ls_tp_emit.c`) |
| **Signing** — Ed25519 admission + baked-in public key | `ls_sig.c` `ls_sig.h` · `ls_sig_pubkey.h` (generated) | yes (`.c`) |
| **Audit** — one record per control-plane op + JSON emit | `ls_audit.c` `ls_audit.h` · `ls_json.h` | yes (`.c`) |
| **Maps / helper glue** — BPF-map support and host-side glue | `ls_map.h` `ls_map_glue.h` | header-only |
| **Utility / ABI** — byte-swap; the loader/trampoline/binding wire ABI | `ls_swap.c` · `shield_abi.h` | yes (`ls_swap.c`) |
| **Built-in program (data)** — a compiled shield as bytes, armed only if `LS_SHIELD_BUILTIN=1` (default **off** since 2026-08-31) — a boot self-test, *not* the delivery path | `ls_shield_blob.h` | compiled in via `ls_vm_load.c`, armed opt-in |
| **Test harness — build-box only, NOT in `tmm`** (absent from `filelist`) | `harness.c` | no |

Plus 2 whitelist snapshots under `src/compile/` (`{debug,default}_whitelist_x86_64.pre-ubpf`).
The `ls_ctx_reg*` per-hook ctx-builder registry that earlier versions of this section listed has
been **superseded** by CO-RE + the generic ctx and is gone from the tree.

**And one line in each of `src/compile/{debug,default}_whitelist_x86_64`:** `g_ls_audit`. That
file is TMM's exact manifest of mutable global state and the link fails on any difference in
either direction. The audit trail cost a build cycle here: its first version declared five
separate statics, plus a sixth in `ls_vm_load.c` for the last reply, and the link refused all six.
Folding them into one struct was the right answer rather than adding six manifest lines — the gate
exists to make new global state a deliberate decision, and six names for one feature is six
decisions where there is one. **Predict the symbol with `nm` on the object and pre-add it**; a
guessed pre-add costs the cycle it was meant to save, because the manifest is exact in both
directions.

## 2. `src/compile/filelist`

**Seventeen lines as of 2026-08-20, not the eight this section described until then.** The count
matters less than the two rules: the LAST line is the one to get right (see §5), and a header-only
change compiles nothing, because this directory has no `.d` files — which is why
`env/scripts/bnk-sync-substrate.sh` deletes the objects rather than trusting make.

`filelist.mk` is GENERATED from `filelist`. Adding a line here without deleting the generated copy
leaves the new source uncompiled while the build reports success.

**THREE include paths on the `UBPF` option, and the third is the one that gets forgotten.**
`vm/inc` for `ubpf.h`, `build/vm` for the cmake-generated `ubpf_config.h`, and **`src/base` for
`ls_sig_pubkey.h`** — which `ls_sig.c` includes in **angle brackets on purpose**, so that a
generated key beats any copy committed next to the source (see the note at the top of `ls_sig.c`;
getting that wrong made a signature test verify against a stale key and report a failure of its own
construction). Angle brackets mean it must be found on an `-I` path, and being in the same directory
as the `.c` file is not enough. This block was missing that third path until 2026-08-21, when a
from-nothing rebuild stopped at `ls_sig_pubkey.h: No such file or directory`.

```
UBPF = CFLAGS += -I$(TOPDIR)/.ubpf/vm/inc -I$(TOPDIR)/.ubpf/build/vm -I$(TOPDIR)/src/base
base/ls_vm_config.c   STDINC UBPF
base/ls_vm_load.c     STDINC UBPF
base/ls_vm.c          STDINC UBPF
base/ls_tp_emit.c     STDINC UBPF
base/ls_sig.c         STDINC UBPF
base/ls_audit.c       STDINC UBPF
base/ls_ctx_reg.c     STDINC UBPF
base/ls_ctx_reg_rst.c STDINC UBPF
base/ls_ctx_reg_sslerr.c STDINC UBPF
base/ls_ctx_reg_h2abort.c STDINC UBPF
base/ls_ctx_reg_parse.c STDINC UBPF
base/ls_ctx_reg_alpn.c STDINC UBPF
base/ls_tramp.c       STDINC UBPF
base/ls_tramp_asm.c   STDINC
base/ls_swap.c        STDINC
base/ls_arm.c         STDINC
base/ls_flow_cookie.c
base/ls_prep.c
```

**AND TWO LINES IN THE SSL MODULE'S OWN SECTION OF THE SAME FILE**, which this block omitted until
2026-08-21. `ls_ssl_cookie.c` and `ls_ctx_alpn.c` are copied into `modules/hudfilter/ssl/` because
they touch `struct ssl_ctx` and must compile in that module's include world — §1's table says so and
`bnk-sync-substrate.sh` puts them there — but nothing compiled them, because `filelist` never
mentioned them. Add them next to the module's other entries, not with the `base/` block:

```
modules/hudfilter/ssl/ls_ssl_cookie.c
modules/hudfilter/ssl/ls_ctx_alpn.c
```

The symptom is a **link** failure two thousand objects later, and it names the callers rather than
the missing files:

```
ls_ctx_reg_sslerr.c:19: undefined reference to `ls_ssl_cookie'
ls_ctx_reg_alpn.c:20:   undefined reference to `ls_ctx_alpn_build_v'
```

Both files were sitting in the tree, correct and unread. On the previous build box these entries
were added by hand once and lived only in that box's `filelist` — which is precisely what
`.tree-expected-delta` records as `M src/compile/filelist` without being able to say *what* the
modification was. The manifest can only carry names, so the substance has to live here, and until
today two of the eighteen-plus lines did not.

## 3. `src/compile/default_whitelist_x86_64` and `debug_whitelist_x86_64`

TMM's build fails if a global appears that the whitelist does not list. It is a manifest checked
**both ways**, so a stale entry fails as loudly as a missing one.

**That bidirectionality caught a real bug on 2026-08-17, and nothing else did.** The five
`ubpf_register*` calls that make maps work existed only in the build box's copy of `ls_vm.c` and were
never carried back here; copying `substrate/` over that tree deleted them. With nothing calling
`ls_map_reloc`, the compiler removed `g_ls_shapes` as dead and the manifest reported a name it
expected but could not find. Every other signal said the system was fine: programs loaded, PREVAIL
verified them, they ran, and every map lookup returned empty --- indistinguishable from a program
whose predicate never matches.

So: **run `env/scripts/bnk-check-tree-sync.sh` BEFORE copying `substrate/` into the tree, every
time.** After the copy the evidence is gone, because the tree matches the repo by construction. That
run also found the trampoline assembly (`ls_tramp_asm.c`) and the whole per-hook ctx dispatch
existing only on the build box --- 12 divergences, 5 files carried back into git. 23 symbols are added to **each**
file:

**Two more since that audit:** `g_armed_count` and `g_armed_slot`, added to both
whitelists by the shared-slot guard in `ls_arm.c`. That brings the tree's additions to
32.

**One more, 2026-08-18: `g_ls_names`**, from making map identity the symbol name
rather than the shape (`ls_map_glue.h`). 33. It cost a build, and the way it cost one
is worth recording because it will happen again: the FIRST build after the change
passed `diff-globals` cleanly and produced a binary WITHOUT the change. There are no
`.d` files in `src/compile`, so make has no dependency edge from an object to the
headers it includes --- a header-only edit recompiles nothing, and the gate cannot
catch a symbol that was never compiled. The gate only fired on the build after the
objects were forcibly removed. `env/scripts/bnk-sync-substrate.sh` now does that
removal as a step, and verifies it by counting rather than announcing it: the objects
are root-owned from inside the toolchain container, so a plain `rm -f` prints
"Permission denied" and keeps going.

**THE AUTHORITATIVE LIST, recovered from a from-nothing rebuild on 2026-08-21.** The gate's own
diff is the generator: build, let the link fail, and it prints exactly the symbols to add, with a
sign telling you which direction. On a clean tree it named **30**, all `+`, nothing stale:

```
_initialized  _ubpf_filter_instruction_lookup_table  _ubpf_instruction_filter  atfork_done
ebpf_atomic_store_immediate_enumerated  ebpf_movsx_alu64_offset_enumerated
ebpf_movsx_alu_offset_enumerated  g_cfg  g_filebuf  g_installed  g_loader  g_loader_running
g_ls_audit  g_ls_names  g_ls_nshapes  g_ls_shapes  g_origin  g_pad  g_prep  g_prev
g_prog_stack  g_ready  g_slots  g_sock_path  g_tp_seg  g_tp_seg_tried  g_tp_seq
ls_prep_timer  ls_prep_timer_on  register_map
```

**Note the split, because it changes who owns the list.** Ten are the substrate's own state
(`g_ls_*`, `g_prep`, `g_slots`, `g_sock_path`, `ls_prep_timer*`, `g_ready`, …). The other twenty come
from **uBPF's translation units**, now linked into TMM — `_ubpf_*`, `ebpf_*_enumerated`,
`register_map`, `atfork_done`. So this list is a property of *the vendored revision as much as of our
code*, and bumping the uBPF pin will change it. That is a second reason not to trust a hand-kept
prose list: half of it is somebody else's.

**Do not pre-add from memory. Regenerate.** Build, read the diff, add what it names — the runbook's
advice to predict and pre-add only pays when the prediction is measured, and here the measurement is
free because the gate performs it. Both files also get a `.pre-ubpf` copy first, which is why
`.tree-expected-delta` lists two of those.

**The older prose below is kept for the record and should not be used.** An audit on 2026-08-17
found the tree adds **30** symbols, not the 22 written here: `g_ls_shapes`, `g_ls_nshapes`, `g_tp_seg`,
`g_tp_seg_tried`, `g_tp_seq` and `_ubpf_instruction_filter` were added to the tree
and never added here. The authority is now `substrate/.tree-expected-delta` plus the
build's own whitelist files; regenerate this list rather than trusting it.

```
atfork_done                              g_installed
ebpf_atomic_store_immediate_enumerated   g_loader
ebpf_movsx_alu64_offset_enumerated       g_loader_running
ebpf_movsx_alu_offset_enumerated         g_origin
g_cfg                                    g_pad
g_filebuf                                g_prep
g_prog_stack                             g_prev
g_ready                                  g_slots
g_sock_path                              ls_prep_timer
_initialized                             ls_prep_timer_on
register_map                             _ubpf_filter_instruction_lookup_table
_ubpf_instruction_filter
```

Three traps here, each of which cost a build:

- **The two whitelists are not the same file.** Appending the same block to both is wrong; they
  differ. Take each side from that build's own `Autogenerated file:` output rather than editing by
  hand.
- **It lists global *variables*, including file-scope statics** — not functions.
- A heredoc that writes literal `\n` corrupts the file in a way the build reports as a missing
  symbol somewhere unrelated.

## 4. `Makefile.overrides`

A new file, consumed at a sanctioned extension point --- `Makefile.inc:116` includes it when it
exists. Its whole contents:

```make
CFLAGS      += -I$(TOPDIR)/.ubpf/vm/inc
DEVFS_LIBS  += $(TOPDIR)/.ubpf/build/lib/libubpf.a
CFLAGS_OPTIMIZE += -fpatchable-function-entry=5,0
```

The flag reserves 5 bytes after `endbr64` at every function entry the build emits out-of-line.
Applied to **every TMM compilation**; it reaches none of the two dozen separately-built components,
which is a property of how the binary is assembled, not of the flag.

**The third line was `:=` until 2026-08-18, and that was a defect.** It read

```make
CFLAGS_OPTIMIZE := -O2 -fpatchable-function-entry=5,0
```

which REPLACED the tree's own selection rather than appending to it. `Makefile.inc:96-100` chooses
`-Os` when `VADC_TRIAL=yes` and `-O2` otherwise, so the override silently forced a VADC trial build
from `-Os` to `-O2` --- a change in build behaviour well beyond adding a flag, and one nobody asked
for. It went unnoticed because the default build selects `-O2` anyway, so the common case was
identical and only the trial variant was affected.

Verified by expanding the variable rather than by rebuilding:

| build | before (`:=`) | after (`+=`) |
|---|---|---|
| default | `-O2 -fpatchable-function-entry=5,0` | `-O2 -fpatchable-function-entry=5,0` (unchanged) |
| `VADC_TRIAL=yes` | `-O2 ...` --- **forced** | `-Os ...` --- the tree's choice preserved |

Ordering that makes `+=` correct: `src/compile/Makefile:46` includes `Makefile.inc`, which sets
`CFLAGS_OPTIMIZE` at `:96-100` and then includes this file at `:116`, so the append lands on
whichever level the tree chose. `src/compile/Makefile:69` clears the variable only under
`DISABLE_OPTIMIZATION=YES`, where losing the pads is the right outcome.

## 5. Why `ls_prep.c` has no `STDINC` — the include-world split

Files marked `STDINC` in `filelist` get the standard C library. Files without it get TMM's
`-nostdinc` universe. `INIT_FUNC` and the timer API live in the second; `bool` and `size_t` live in
the first. So the work stays in `ls_vm_load.c` (STDINC) and only a `void(void)` — `ls_vm_bootstrap`
— crosses the boundary.

**Do not "simplify" this by redeclaring the real prototypes on the other side.** `bool` returns in
`al` while `int` reads `eax`, and the upper bits are not guaranteed: that is a genuine ABI mismatch,
not a style question.

## 6. How the bootstrap runs without touching F5 source

`ls_prep.c` registers through TMM's own init linker set:

```c
INIT_FUNC(INIT_LATE, ls_startup);
```

`INIT_LATE` (-10) sits in the "events in threads" group, so it runs **once per TMM thread with `tid`
valid** — which is what the tid-0 timer election and the per-thread VM state require. The same
mechanism is used by `urlcat`, `pem_lib` and `license_pgo_gen`, so this is a documented TMM
extension point, not a trick.

An earlier version put 26 lines of bootstrap in `http_psm_init()`. That worked and was still wrong:
bringing up a general-purpose VM has nothing to do with HTTP protocol security, and it was an edit
to F5's source. `http_psm.c` is now pristine.

## 6b. The tracepoint — the one place an F5 source file IS edited

Everything above adds files. This section does not, and the distinction is the point.

**The shield modifies no F5 source, and must not.** It targets a TMM that is *already running* —
the binary exists, so the only way in is patching a function entry. That constraint is what makes
the shield claim worth anything.

**A tracepoint is a build-time decision about what TMM should expose**, so a deliberate call site is
the correct mechanism, not a compromise. Two attempts to synthesise one from a patched entry failed
structurally: an entry runs *before* the function writes its outputs, and the interesting failure
paths (`http1x_psm_method`, `http1x_psm_header_count`, `http1x_psm_header_crnl`) are defined in
`http1x.h`, so the compiler folds them into their callers and there is no symbol to arm.

### New files

| this repo | TMM tree |
|---|---|
| `substrate/ls_tp.h` | `base/` — the boundary declaration, dependency-free |
| `substrate/ls_tp_emit.c` | `base/` — STDINC side: forwards to `ls_vm_call`, then publishes to the ring |
| `substrate/ls_tp_ring.h` | `base/` — the shared-memory segment: layout, per-thread claim |
| `substrate/ls_ring.h` | `base/` — the ring itself. **Was bench-only**; the producer needs it in the tree |
| `substrate/ls_ctx_rst.h` | `base/` — the reset record + builder |
| `substrate/ls_map.h` | `base/` — per-thread map storage |
| `substrate/ls_map_glue.h` | `base/` — the three uBPF callbacks (relocation, bounds, helpers 1/2/3) |
| `substrate/ls_tp_http.h` | `modules/hudfilter/http/` — record + builder, `static inline` |

`filelist` gains one line:

```
base/ls_ctx_reg.c     STDINC UBPF
base/ls_ctx_reg_rst.c STDINC UBPF
base/ls_ctx_reg_sslerr.c STDINC UBPF
base/ls_ctx_reg_h2abort.c STDINC UBPF
base/ls_ctx_reg_parse.c STDINC UBPF
base/ls_ctx_reg_alpn.c STDINC UBPF
base/ls_tp_emit.c     STDINC UBPF
```

**And whitelist entries, in *both* files.** So far: `g_tp_seg`, `g_tp_seg_tried`, `g_tp_seq` from the
ring producer, then `g_ls_shapes`, `g_ls_nshapes` and `g_ls_names` from the map glue.

Insert in SORTED position (`sed -i '/^g_ls_nshapes$/i g_ls_names'`) rather than
appending and re-sorting: these are F5 files and the smallest possible diff is the
point. Then check two things --- that the file is still sorted, and that the new line
carries **no trailing carriage return**. `script -qec` emits CRLF, and an entry with a
`\r` does not match the symbol, so `diff-globals` fails with a diff that looks exactly
like the one just fixed. That has happened twice.

This has now cost four builds. **Adding any file-scope static to this substrate costs a whitelist
edit in both files**, and `diff-globals` reports it as a link failure with a diff rather than a
compile error, so it does not look like the thing it is. Check before building, not after.

Useful detail learned the third time: `__thread` variables do **not** appear in the globals list.
`g_ls_maps` and `g_ls_maps_storage` are thread-local and needed no entry; only the two process-wide
ones did.

`ls_tp_http.h` is a header compiled *inside* `http1x.c`, so it inherits that file's include world
exactly — no `-I` to guess and no separate object needing to be taught where TMM's headers live.
That is why the builder is a `static inline` rather than its own translation unit.

### The edits to F5 source — also captured as a patch

Both call sites live in [`tmm-tree-callsites.patch`](tmm-tree-callsites.patch), regenerated with
`git diff` in the TMM tree. The new files are recoverable from this directory; the call sites are
two lines each and existed **only** in a build box's working tree until that patch was committed.

### The two call sites — and why there are two

**There are two different static functions named `http_process_client_headers`**: `http1x.c:1031`
taking `struct http1x_pcb *`, and `http.c:7767` taking `struct http_scb *`. Both are file-scope, so
nothing collides and nothing warns. Both call `http_parse_client_headers`, which is why an entry
hook on the parser fires for either and **cannot tell them apart**.

Only `http.c`'s survives as a symbol — `addr2line` on `0xca5c80` resolves to `http.c:7769`. The
first version of this tracepoint went into the `http1x.c` one and never fired: 9 requests returned
200 with `fired=0`.

So the builder takes **scalars, not a pcb**, and one tracepoint serves both sites:

```c
 #include <local/base/ls_tp.h>
 #include "ls_tp_http.h"      /* AFTER the file's own headers: it includes nothing itself */
 ...
 out:                          /* every path converges here */
     ...
+    ls_tp_http_hdrs_emit(hd, (int)err, (int)*passthru, (int)scb->reject_reason);
     return err;
```

`http1x.c` passes `pcb->hd` and `pcb->reject_reason` instead. Binding the builder to a pcb type is
what forced the wrong choice the first time.

### Why the call site cannot alter traffic

`ls_tp_emit` returns `void`, so the call site has no way to receive a verdict and therefore no way
to act on one. A program loaded behind this tracepoint cannot change the request **even if armed in
ENFORCE**. That is structural rather than a mode setting, and it is deliberate: relying on MONITOR
alone has already gone wrong once, when a tracepoint armed under a stale ENFORCE setting turned 200s
into 404s.

### The ring producer

`ls_tp_emit` publishes the same record twice, to two independent consumers:

| | answers | needs |
|---|---|---|
| the VM | "how many were malformed" — two counters | nothing |
| the shared-memory ring | "show me that request" — the bytes | a drain agent |

The ring is **off unless `LS_TP_RING` names a path**, the same discipline as the loader socket;
unset costs a load and a branch. Two new files: `base/ls_tp_ring.h` (segment layout, per-thread
claim) and the rewritten `base/ls_tp_emit.c`. No filelist change — `ls_tp_ring.h` is a header.

**One ring per thread, by construction.** `ls_ring.h` is single-producer, and that is a correctness
precondition, not a tuning choice. `g_slots` in `ls_vm.c` is a plain process-global despite
`ls_prep.c` describing "per-thread VM state", and the TMM process here runs three threads. Each
thread claims its own ring by atomic index, so the precondition holds whatever the thread model
turns out to be — and `check_tp_ring.c` asserts the rings are distinct rather than assuming it.

**`STREAM`, not `RECORD`.** Full means drop the new record and count it. A streaming feed must never
have a record pulled from under a mid-read consumer, and the poll loop must never wait on that
consumer. A counted gap, never a silent one.

**The Kubernetes trap.** A sidecar sharing `/dev/shm` needs an `emptyDir` with `medium: Memory`
mounted at the same path in *both* containers. Without it the sidecar maps its own empty tmpfs and
sees a valid, empty segment — which reads as "no traffic" rather than as a misconfiguration.
`check_tp_ring.c` covers the adjacent case: an uninitialised segment is refused, not decoded.

### Validating it

The record is only worth having if it can be fired on demand. Each row is an input chosen in advance
and a counter movement predicted before running it:

| send | expected |
|---|---|
| `curl http://vip/` | `fired`+1, `safe_returns`+0 |
| `curl -X BOGUS http://vip/` | `fired`+1, `safe_returns`+1, `reason=METHOD` |
| 200 × `-H` | `fired`+1, `safe_returns`+1, `reason=HEADER_NUMBER` |

`make check` runs `check_tp.c` — 18 assertions over mock structs: the record is 40 bytes on both the
host and program sides, the five `f_invalid_*` bits compose **by name**, and a null `hd` emits a
well-formed row instead of faulting. It cannot prove the field names match TMM's; only the TMM build
does that, which is exactly why they are composed by name rather than masked from a byte offset.

## 7. Packaging traps

**`make clean_rpms` between `make tmm` and `make container`, or the image ships a stale binary.**
This one is silent and cost two builds. `make container` runs `alien` over `RPMS/`, so if the RPM
was not regenerated the deb is built from the *previous* binary — the build tree is correct, the
image is not, and nothing warns. `make tmm-gdb` gets this right (`make tmm && make clean_rpms &&
make … container`); a hand-rolled `make tmm && make container` does not.

The symptom is the worst kind: everything reports success, the deployed code silently predates your
edit, and you debug the wrong layer. Check a string you added is actually in the image before
shipping:

```sh
cid=$(docker create <tag>); docker cp "$cid:/usr/bin/tmm64.no_pgo" /tmp/b; docker rm "$cid"
strings /tmp/b | grep -c '<a string from your change>'
```


These are not substrate issues but they will cost hours:

- `Dockerfile.runtime:53-54` overrides `tmm` → `tmm.debug` when a debug binary is present.
- `make clean_rpms` does **not** clear `docker_build/DEBS`.
- A stale `BUILD_x86_64/` gives `gcc: fatal error: no input files` on an unrelated object.
- **Packaging re-links the binary**, so its build ID differs from the build tree's. Any address you
  arm must come from the matching `tmm-debuginfo` deb, never from the build tree.

See [`../env/bnk-dev-runbook.md`](../env/bnk-dev-runbook.md) for the image ship, per-node
`ctr` import, rollout and verify steps.
