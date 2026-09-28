# Named embedded-structure traversal: P17 validation

**MEASURED, 2026-09-24:** the `tmmtrace` authoring extension passes native-layout execution
fixtures, real-TMM relocation/admission checks, and three signed monitor probes on live HTTP/1
traffic. The authoring code and regenerated catalog are installed on the build box. The runtime
remains build `c3b81927dfdcc31137cd8212b5e23bb85677a06c`; this extension needed no TMM rebuild.

Falsifier: [P17](02-RESEARCH-PARAMETERS.md#p17--does-embedded-structure-dsl-traversal-preserve-the-intended-field-access).
Every cached file below is registered with its full hash in [SOURCES.md](SOURCES.md).

## Contract and implementation

`args.a.b.value` and `arg1.a.b.value` may mix pointer edges and named embedded structs.
`gen_type_catalog.py` adds `__embedded__`, peeling typedef/qualifier wrappers while preserving
the existing scalar/pointer catalog. Code generation emits complete nested declarations in
dependency order. Pointer hops use a bounded probe read and decline on NULL/read failure;
embedded hops compute a member address without reading its contents as a pointer.

```text
BUILD BOX
  Packaged TMM + matching BTF → scalar/pointer/embedded catalog
  DSL → clang-18 CO-RE object → resolved field offsets → stripped object
      → authenticated target record → final PREVAIL → signed program

RUNNING TMM
  Signed program → admission → entry/exit attachment → bounded field reads
                → monitor counters → disarm, restore NOPs, disable slot
```

Anonymous aggregates, unions, arrays, bitfield reads, expanded argument ABIs and semantic AI
events are outside this slice. Legacy catalogs lack `__embedded__` and retain pointer-only
traversal. Conflicting or cyclic embedded declarations are refused.

## 1. Native-layout fixtures — off TMM

`substrate/check_embedded.c` supplies native `offsetof` values, padded struct layouts and known
values. `check_embedded.py` generates BPF with clang-18, relocates it with the existing C
relocator, compares every relocated offset against the native oracle, verifies the final bytes,
and executes them with the pinned uBPF interpreter **and** JIT.

Covered: nested-only, pointer→embedded, embedded→pointer, pointer-only, scalar argument/field,
explicit argument selection, two fields of the same nested type, typedef/const/volatile wrappers,
embedded-only catalog owners, NULL/unreadable pointers, bitfields including bit zero, unsupported
aggregates, conflicting/cyclic metadata and old catalogs. Nested-only reads use one helper;
the mixed paths use two. An intentionally unrelocated object returns the wrong value in both
engines: the fixture detects bad offsets instead of merely checking acceptance.

**Witnesses:** compiler/native layout and PREVAIL are TOOL; helper-read counts and execution
expectations come from our fixture (SELF). This is not the TMM helper or data plane.

```sh
# On the x86-64 build box, after staging current sources:
UBPF=/home/starin/code/tmm/.ubpf \
  make -C /home/starin/eob-tmm-staged/substrate check-embedded
```

Receipt: `evidence/cache/embedded-fixtures-20260924.log`, including source/tool hashes and pins.

## 2. Real-TMM authoring — build box

`embedded-authoring-driver-20260924.py` is retained beside its log. It regenerates the catalog
from the current build's BTF, asserts **every previous catalog key is unchanged**, and adds
embedded edges for **3,184 owner types**. It checks four actual expressions: the three live cases
below and `fentry/http2_http_data_to_frames /arg0.http_data.ci.http.cache.cur_entries > 0/ { count() }`.

The independent Python relocation walker and C relocator agree on **12/12 offsets**, with zero
unresolved entries, mismatches, non-reproducible objects or fatal bitfield hazards. All four
objects pass packaged-target binding, final pinned PREVAIL and signing with a monitor ceiling.
The HTTP/2 program was **not armed or executed** in this experiment.

The new `~/lstools/types.json` has SHA-256
`49b34181c76bb76089d538bed66c46e841f96ba5b860ca484b8f60f99aee0ff2`;
the prior copy is `types.json.pre-embedded-20260924`. Objects and originals with relocations remain
under `~/embedded-p17-20260924`. Only the three signed HTTP/1 programs travelled to datkube.

## 3. Live HTTP/1 probes

Pod `f5-tmm-7597dfff8b-28s9z`, UID `42259fbc-3303-492a-95b1-9146b4105583`, remained stable with
zero restarts. Executing ELF SHA-256:
`a4b9e777a1daccd8c2b8c7f1aa7eba920b6040253f45f017605ea0a5f0a8afd7`.
Its runtime receipt matched, and the named bulk catalogs were absent from `/usr/share/ls`.

| Probe on `http_parse_client_headers` | Requests / HTTP 200 | Fires | Matches | Errors |
|---|---:|---:|---:|---:|
| `fexit`, `args.cache.cur_entries > 0` | 16 / 16 | 16 | 16 | 0 |
| `fexit`, `args.cache.cur_entries == 0` | 16 / 16 | 16 | 0 | 0 |
| `fentry`, `args.xfrag_head.tqh_first.len > 0` | 16 / 16 | 16 | 16 | 0 |

After **each** disarm, `/proc/24/mem` at `0xccc604` showed `9090909090`; eight further HTTP 200s
left the counters unchanged. Final slot 2: `mode=0 gen=5 fired=80 safe_returns=64 errors=0`.
The disposable HTTP/1 fixture was deleted. **Matches are monitor test results, not blocked requests.**

Counters are SELF; curl, packet capture, process-memory readback and pod identity are TOOL/KERNEL.
The live run establishes these predicates at these hook times, not independently exact numerical
field values across all TMM layouts. Exact values were checked in the native fixtures.

## 4. Failed baseline attempts and the network finding

Initial attempts stopped **before LOAD**: the backend answered locally and the listener reported
`Programmed=True`, but proxy requests timed out. Twelve warm-up attempts did not recover it, and
a gratuitous ARP announcement for the backend did not resolve it. These failed assumptions are
retained in `embedded-live-warmup-failed-20260924.log` and `embedded-live-network-failed-20260924.log`.

Packet capture showed the intended TMM sending SYN from MAC `02:30:76:e6:9d:80`; the backend
sent SYN-ACK, then received RST from **`22:d1:90:5b:dd:9d` using the same `22.22.22.150` IP**.
The other MAC's owner was not identified. The successful run independently captured
**both MACs answering ARP for that IP**;
this time the intended TMM won and traffic completed.

The driver includes a fallback to pin only the disposable backend's neighbor to the selected
TMM; the fixture now requests `NET_ADMIN` for it. **The successful run recovered naturally before
taking the pin branch, so the fallback is not claimed validated.** No TMM/controller restart was
used. `SYMPTOMS.md` records the literal timeout.

## Limits

One function, one stable pod and this HTTP/1 configuration were exercised live. Pointer→embedded
execution is demonstrated in the native fixture and verified against real HTTP/2 metadata, not
live on the HTTP/2 path. These results do not establish concurrency safety, universal named-type
matching, enforcement suitability, performance or AI gateway coverage. The deployed binary still
carries the deliberately reverted CVE-2025-41414 fix documented in `catalog-free-deployment.md`.
