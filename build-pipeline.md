# The build pipeline: what has to be generated so that nothing has to be rebuilt

The claim this engine is demonstrated on is one sentence: **name a function in a running TMM,
get a verified program armed at its entry, with no rebuild and no restart.** Nothing in that
sentence mentions a build.

It is only true because three files were generated when TMM was built. Each answers a
question that cannot be answered at arming time, and each is refused if it describes a
different binary than the one running. This document is the list, the order, the cost, and
the boundary. It is the least interesting part of the system and the part that has to be
right; a stale artifact here is indistinguishable from success until you look at a counter
that never increments.

**Audience note.** This is written for a TMM engineer who will ask "so what does your build
add to mine". The answer is: one compiler flag, three generated files, and a container layer
on top of the image `make container` already produces. No F5 build stage is replaced or
reordered, and nothing in the F5 build depends on any of it.

---

## 1 · What is generated, per build

Three files, all keyed to the binary's GNU build id, all generated from the **packaged**
binary rather than the build tree's.

| artifact | the question it answers | producer | size | cost |
|---|---|---|---|---|
| `hook-index.tsv` | *Can this name be armed, and where?* — entry address, pad shape, whether the first instruction can be relocated | `substrate/mk_hook_map.py --index` | 3.4 MB | **20s** |
| `hook-map.json` | the same, in full, with per-symbol detail for tooling that wants more than the loader needs | `substrate/mk_hook_map.py -o` | 30.9 MB | same pass |
| `signatures.tsv` | *What does this function take?* — parameter names, types, and the kind each maps to (scalar, string, blob, opaque) | `substrate/mk_probe.py --build-index` | 6.5 MB | **2m9s**, one DWARF walk |

Both index producers need `pyelftools` (pinned at 0.33 on the build box) and nothing else.

Two indexes rather than one, because they answer different questions and either is useful
without the other. A parameterless function has an address and no signature entry. A function
the optimiser inlined away has a signature and no address. Merging them would force every
consumer to handle both absences.

### Why `signatures.tsv` is a build step and not a lookup

`substrate/mk_probe.py` generates a probe — the record layout **and** the bytecode that fills
it — from a function's parameters. Finding those parameters means walking every compilation
unit in a 146 MB debug-information file. Measured: **1m54s** for one function.

The walk costs the same whether you want one signature or all of them. So it happens once, at
build time, and every later lookup is a dictionary hit: **0.10s**.

That number is the whole reason this stage exists. "Name a function, get a running probe" and
"name a function, wait two minutes" are different products, and only one of them gets used.

The index is verified faithful rather than assumed: for the five functions with a
DWARF-generated baseline (`rst_why`, `http_abort`, `http2_goaway`, `ssl_hs_drop`,
`flow_input_drop`), the generated `.bpf.c` is **byte-identical** whether produced from the
index or from a full DWARF walk.

---

## 2 · The order is forced, and it looks circular

The indexes must be generated from the binary that **ships**, not the one in the build tree,
because packaging re-links and every address moves. But the packaged binary only exists after
`make container` has produced it.

So the indexes cannot be part of the runtime image build. They are a **layer on top of it**:

```
  0.  make                     TMM builds. One added flag: -fpatchable-function-entry=5,0
                               in CFLAGS_OPTIMIZE. Plus new files and filelist entries;
                               no existing F5 function body is edited.
                                 |
  1.  make container           the DEB pair. tmm_*.deb carries the binary that runs;
                               tmm-debuginfo_*.deb carries the symbols and DWARF.
                                 |
  2.  mk_hook_map.py           hook-index.tsv + hook-map.json      (from the DEB pair)
  3.  mk_probe.py              signatures.tsv                      (from the DEB pair)
  4.  bnk-build-programs.sh    *.bpf.o --- compiled AND verified   (from substrate/shields)
                                 |
  5.  bnk-bake-tools.sh        one container layer: the three artifacts, the loader client,
                               the record reader, the verified programs. Asserts, inside the
                               image, that every artifact's build id matches the binary
                               /usr/bin/tmm actually resolves to.
                                 |
  6.  bnk-ship-image.sh        transfer and roll out.
```

Steps 2–6 touch no F5 build file. That is a consequence of the layering, not an extra
discipline on top of it.

---

## 3 · Where each stage runs, and why it is split

| stage | needs | runs on |
|---|---|---|
| 0–1 build, package | the TMM tree | build box |
| 2–3 indexes | the DEB pair, `pyelftools` | build box |
| 4 compile + **verify** | `clang -target bpf` **and** PREVAIL | dev sandbox / CI |
| 5 bake | Docker, the base image, all artifacts | build box |
| 6 ship, arm | the cluster; nothing else | target |

Stage 4 is split off deliberately, and not because of where the tools happen to be installed
today. It is the shape the production pipeline is meant to have: **compile in dev or CI,
verify and sign at F5, load on the target and nowhere else.** The target needs no compiler, no
verifier, and no debug information — it needs bytecode that something else already vouched
for. Keeping the split visible in the scripts keeps it from being quietly collapsed later,
which is how a verifier ends up on a data-plane box.

---

## 4 · The gates, and what each one caught

Every gate here exists because the failure it catches has happened.

**Build id on every artifact.** On 2026-08-17 a stale address armed a nop pad 64 bytes past
`rst_why`. The patch succeeded, `OK ARMED LIVE` printed, and nothing fired across 16,000
requests — a pad cannot distinguish itself from another pad. Every generated file now carries
the build id of the binary it describes; `ls-load.py` reads the running process's own
executable via `/proc/<pid>/exe` and refuses on a mismatch.

**Both indexes checked against each other, then both against the binary.** They are produced
by two different tools from one DEB pair, so a mismatch means one of them read a stale file.
`bnk-bake-tools.sh` compares them before building, and `ls-verify-layer.sh` re-checks both
against the resolved binary from inside the finished image.

**`/usr/bin/tmm` must not resolve to a debug build.** `Dockerfile.runtime` points it at
`tmm.debug` whenever a debug binary is present, and the debug build overrides
`CFLAGS_OPTIMIZE` — which is where the padding flag lives. So that binary has no entry pads
and nothing in it can ever be armed; arming fails with "no pad", which reads like a stale
address and is not. Four images shipped that way, three reaching the cluster.

**Negative tests must still be refused.** `bnk-build-programs.sh` asserts the expected verdict
in *both* directions. Programs named `reject_*` exist to be rejected by PREVAIL, and a build
where `reject_termination.bpf.c` verifies clean is a worse failure than one where a real
program does not — it means the verifier stopped catching what that program was written to
trip. Current set: **16 verified and emitted, 2 correctly refused, 0 unexpected.**

**PREVAIL's flags are passed explicitly.** Its defaults are permissive: `--termination` is
*"Default: ignore"*, `--allow-division-by-zero` is *"Default: allow"*, `--strict` is off.
"Verified" without them means materially less than it sounds.

### The defect that argues for the gates

Building this pipeline surfaced one, and it is the exact class the gates exist for.

`tmm-debuginfo_*.deb` contains **two** debug binaries with **different build ids**:

```
  usr/lib/debug/usr/bin/tmm64.debug           97 MB   47a10fc4...   PGO build
  usr/lib/debug/usr/bin/tmm64.no_pgo.debug   146 MB   74ed5caf...   what /usr/bin/tmm resolves to
```

`mk_probe.py` selected the debug file by taking the first one over 10 MB in directory-walk
order. That is `tmm64.debug` — a build TMM does not run. Both are builds of the same source,
so the generated probes verified clean and read plausible fields. The two builds differ in
**3,132 functions** (66,905 with parameters versus 63,773), because profile-guided
optimisation changes what gets inlined and therefore which functions have parameter
information at all.

Nothing in the generated output would have said so. The cross-index build-id comparison added
in step 3 refused it immediately: `47a10fc4 != 74ed5caf`. Selection is now **by build id**,
matched against the runtime package, with no inference from filenames — `no_pgo` being the
shipped one is a property of this build's configuration, not a rule.

The same investigation found that the repository held **six** independent implementations of
the build-id read, and that the two pure-Python ones (used inside the container, where there
is no `readelf`) returned a **16-byte id where `readelf` reports 20**. TMM's PGO debug build
declares two adjacent `PT_NOTE` segments with the build-id note straddling the boundary;
per-segment parsing stops at `p_filesz` and truncates. It discriminated builds correctly, so
nothing ever disagreed with it — a gate advertising more than it checked. There is now one
canonical reader (`substrate/ls_buildid.py`), and `substrate/check_ls_load.py` synthesises
both fault shapes and asserts full-width reads against `readelf`:

```
ok    (a) straddle, mirroring tmm64.debug    old parse: 47a10fc43398caa9af9dddbd8bed82ce (32 hex)  now: full 40 hex
ok    (b) 8-aligned property note            old parse: None (0 hex)                               now: full 40 hex
```

Case (a) reproduces the real symptom byte-for-byte. Case (b) is the fault the *first* fix
introduced: alignment is per-note, not per-segment — a `.note.gnu.property` note pads its name
to 8 bytes while a build-id note pads to 4, in the same segment, so no single stride walks
both.

---

## 5 · Costs, measured

On the build box, for build `74ed5caf`:

| stage | wall clock | output |
|---|---|---|
| hook index (both files) | 20s | 71,157 entries under 70,029 distinct names (see the scope note below) |
| signature index | 2m9s | 63,773 functions with at least one parameter, 159,887 parameters |
| compile + verify all programs | ~20s | 16 emitted, 2 refused |
| bake layer | ~30s | one layer on the existing image |
| **per-function probe lookup** | **0.10s** | ctx record + `.bpf.c` + PREVAIL PASS |

**Scope note on the index counts.** The index covers the whole shipped binary, which
includes components other teams own and that are not compiled with the padding flag —
OpenSSL among them. Of the 71,157 entries, 41,148 carry an entry pad and 30,009 do not and
would need their leading bytes relocated instead. **Do not read that split as a coverage
figure.** TMM core is padded throughout, because the flag is in `CFLAGS_OPTIMIZE` and TMM
core is what that builds; the unpadded population is essentially the components outside that
scope. A whole-binary percentage mixes the two and understates the thing being claimed.

All of it is off the data path. None of it runs on a packet, in the poll loop, or on the
target. The only thing the target does is receive bytecode over a socket and patch five bytes.

---

## 6 · What the pipeline does not do yet

Named plainly, because each is a real gap rather than a detail:

- **No signature verification of bytecode.** The loader accepts what arrives on the socket.
  A signing step and an in-TMM check against a baked-in key is the shippability gate, and it
  is not built. Until it is, "only verified programs load" means only that PREVAIL ran
  somewhere upstream, on the honour system.
- **No audit trail.** Nothing records who armed what, when, against which build.
- **The vendored uBPF revision is unrecorded.** The vendored copy carries one patch
  (`substrate/ubpf-patches/0001-jit-scratch-rightsize.patch`) and has no `.git`, and it
  differs from the `508d5e4b` checkout on the build box. Reproducibility hole; PREVAIL is
  pinned at v0.2.6 and unmodified.
- **The cycle budget is advisory.** `budget_pass.py` reports an estimate per program and
  nothing gates on it, because the per-call hook cost that would calibrate it is unmeasured —
  the counter mean is dominated by preemption artifacts. See `load-path-scope.md` §7. Quote no
  per-call number.
- **`mk_probe.py` covers parameters, not derived state.** It reads what a function is handed.
  A field reached by walking a struct pointer needs `bpf_probe_read` and a layout the
  generator does not yet emit.
- **Ambiguous names are refused, not resolved.** 591 names in the index have between 2 and 21
  entries — file-scope statics repeated across translation units, `.isra`/`.constprop` clones,
  and assembler labels. Arming one of those refuses rather than picking a homonym. Correct,
  and less useful than resolving it.

---

## 7 · Reproducing it

```bash
# on the build box, after make && make container
python3 substrate/mk_hook_map.py --debs $DEBS -o hook-map.json --index hook-index.tsv
python3 substrate/mk_probe.py    --debs $DEBS --build-index signatures.tsv

# on the dev sandbox (clang + PREVAIL)
env/scripts/bnk-build-programs.sh $HOME/lstools/shields

# back on the build box
env/scripts/bnk-bake-tools.sh tmm:local tmm:ls
env/scripts/bnk-ship-image.sh verify tmm:ls

# then, per function, anywhere the index is
python3 substrate/mk_probe.py --index signatures.tsv --function rst_why --out probe.bpf.c
```

`env/bnk-dev-runbook.md` has the machine-specific detail: hosts, keys, the per-node image
import, and the rollout.
