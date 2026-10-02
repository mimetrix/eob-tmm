# Sources: every external claim, and the file behind it

Rule: **no cached file, no claim.** A statement about anything outside this repository cites a row here, and every row names a file in `evidence/cache/` with a SHA-256 you can check. A source that could not be retrieved is recorded as `NOT_RETRIEVED` with the reason — never paraphrased from memory.

Regenerate the hashes:

```bash
cd evidence/cache && sha256sum * > MANIFEST.sha256
```

## Retrieved

### Client TLS mode, 2026-10-01

**MEASURED: native tests, pinned build checks and isolated single-worker HTTP/1
traffic.** Contract registered first in commit `053b858`
([TLS-MODE.md](env/ai-traffic/TLS-MODE.md), P23). Target: packaged build
`2ab960fa38e447bab97738e47e1d5b2ce25c401a`, image
`sha256:0b96d57129bc62948f7bb38d7e8dbe4baa9dae5e1aeaed81b0c64b90018c1217`.

Build 06 artifact `agent_activity.bpf.o`, 186,704 bytes, SHA-256
`a15f513534270936b4e999b5b306019e4e7b8ccd7686dca181aea5ff87fd2f23`. Both entries
pass pinned PREVAIL (256-byte stack). GCC 13.3.0 and clang 18.1.3 native tests
pass in interpreter and JIT, including authored chains for every class, the
16-node limit, a cycle, unreadable pointers, cleared context flags, a server-side
SSL entity and two SSL filters. All 26 offsets and bit positions are asserted
against the debug file (SHA-256 `92a14f17…`).

Live attempt 02: three AIMCP virtual servers (plain, client SSL, client SSL with
`peer_cert_mode=request`). 16 combined exchanges; each TLS reading matches the
client's own protocol and cipher ID. Trusted, untrusted and missing client
certificates yield `verified`, `failed` (code 20) and `none_observed`. Identity
stays `unknown`. 32 JSON and 362 HTTP hook calls; zero errors or safe returns.
Both hooks restored; same process; zero restarts. Per-run keys and certificates
were deleted; receipts keep only certificate SHA-256 fingerprints.

Witnesses: INDEPENDENT (PREVAIL), TOOL (compilers, debug-layout check), SELF
(fixture clients, bytecode records, exporter), KERNEL (binary, process, hook
bytes). The client's TLS record is fixture code, not an independent TLS audit.

| Cached file | SHA-256 | Result |
|---|---|---|
| `tls-mode-build-01.json` | `dd28a85aed64d9edeb4ddf5b1e9a0295381f71d0639a4136d2c98b824aa52196` | Retained failure: clang `-Wsign-compare` on the walk loop counter. |
| `tls-mode-build-02.json` | `bf90cd5c9b49e51cbc5d38ef7f11de973645bd11796f0a13c114de5bbe1b187d` | Retained failure: clang could not unroll a loop with early exits. |
| `tls-mode-build-03.json` | `3730522af5fc55aa98800e3fb4a55ea931a3a522ccc2e7b77b6681ae5991b80b` | Retained failure: source snapshot lacked `ls_program.h`. Bytecode and PREVAIL had already passed. |
| `tls-mode-build-04.json` | `d71789171f3c7a076a5035659421f637b5cc7fa7b1ced887f35cae5e880fe12e` | Retained failure: the native test inherited a server-side flow from an earlier case (test setup error, not a probe defect). |
| `tls-mode-build-05.json` | `87c89f443ddd5fa91edba04207ef1a33564bb60d5fef1eb28ffa075c439124ce` | Retained failure after all native tests passed: old-parser header path absent from the new package. |
| `tls-mode-build-06.json` | `f6c9a0aa08321cb3626af2e7503e88b4441cf11cb8bf3107c9f3706b86c01386` | Pass: layouts, PREVAIL, native tests, target-set mutations, old-parser refusal, both signatures. |
| `tls-mode-combine-check-01.json` | `23553a68d5a8cb2073cf8030ce44442b64ef10da0ce9fa9b872393c685faf278` | 11/11 combiner tests on the measured 2026-09-30 journal: eight existing, no TLS claim on ABI 1 records, 24 decoder cases, conflict reporting. |
| `tls-mode-export-check-01.json` | `ee7dceea60a46f64d0dd80631a293cd12afa9954e68d296a0f0dfe2237095b2a` | Retained failure: check copy lacked `MANIFEST.sha256`. |
| `tls-mode-export-check-02.json` | `637727056f454b2997208fd657f651273ef8a9e9edfd79e185b180f63b6247f1` | 6/6 export tests unchanged. |
| `tls-mode-create-01.json` | `fa245ed9393dbbb70da8a536255051d188e932d941bd8a2c030ba0ce1f8daa32` | Isolated fixture with the packaged image and collector API; other containers unchanged. |
| `tls-mode-live-01.json` | `997d69225300c85ff79ae1d57a8e8d6318b23ea6c7f33ccb9967154133094540` | Retained failure before any arm: pylint `no-member` on a generated protobuf field. |
| `tls-mode-live-02.json` | `a6dc1141262440863cfd49b59b708671ad7df0e216122e8ac071e193b9b987b7` | 16 exchanges, readings match the client record, replay identical, hooks restored, zero restarts. |
| `tls-mode-cleanup-01.json` | `3c23e289c8e19fa4fb52aa5cc9a28149323d49f346ef5ca405d03e3ab0df7cec` | Eight-file archive checked; hooks and slots checked; fixture removed; toolchain container unchanged. |
| `tls-mode-evidence-01.tar.gz` | `5691e88cbf369899044778de688f2da47630dd28cf4998acb6693dd211e2f0ba` | Attempt 02 fixture files and journal. Attempt 01 created no files. |

### Program ownership live validation, 2026-09-30

**MEASURED: packaged TMM and isolated single-worker HTTP/1 traffic.**
Image `tmm:PROGRAMS-20260930` has ID
`sha256:0b96d57129bc62948f7bb38d7e8dbe4baa9dae5e1aeaed81b0c64b90018c1217`.
Packaging rebuilds the runtime: its build ID is
`2ab960fa38e447bab97738e47e1d5b2ce25c401a`, distinct from the earlier linked
build. Runtime SHA-256:
`50d5d1e711dc4a79adf1bd1bb30f6c306d36ad75bbda8e7d03998e88a5124fc8`.
The runtime/debug pair, ownership symbols, TLS, image metadata and signing-key
checks pass. The existing HTTP/2 CVE-fix revert remains in the build tree.

The native-qualified two-entry test ELF is rebuilt byte-for-byte, then its
entry sections are renamed and bound to this packaged binary. Executable
section bytes remain unchanged. Both final entries pass pinned PREVAIL before
one `@program-v1` signature is made. That ELF is loaded as two separate owners.

Live attempt 03 passes **18/18 HTTP exchanges and 594 hook records**.
Assertions require the expected request and response bodies and HTTP status 200.
Eight phases cover shared hooks, partial detach, reattach, independent revoke,
replacement with a fresh instance, disable/re-enable and final removal.
Configuration markers and map sequences stay separate by owner. Both entries
share a counter within their owner. A context write does not change the next
owner's observed input. Duplicate attachment, signed-mode-ceiling violation,
wrong/stale instance and stale configuration are refused. Both original entry
pads are restored; the TMM process stays the same with zero restarts.
All eight owner slots are empty at the end. The fixture is archived and removed.

Witnesses: INDEPENDENT (PREVAIL), TOOL (compiler, package and image checks),
SELF (clients, backend, bytecode records and assertions), KERNEL (executing
binary, process identity and hook bytes). This is a two-owner, two-hook monitor
test. Multiple workers, sustained concurrency/cost, enforce composition under
live traffic, loader-timeout stress and collector durability remain unqualified.
The dedicated ring drain is not a new activity-field or collector result.
[Contract, phase table and commands](substrate/PROGRAMS.md#measured-live-result).

| Cached file | SHA-256 | Result |
|---|---|---|
| `programs-package-01.json` | `95dcfe8c7ff945fe7232958294e575165de40ca6c4f482b7db35268c6158cea6` | Fresh DEBs, matching debug/runtime, checked image and preserved source/library inputs. |
| `programs-live-build-01.json` | `4dbdbd25425f41a6e93ad49f149c00523ffe132060bc8b4ff86e442e9da46048` | Native object reproduced; executable bytes unchanged after binding; both final entries pass PREVAIL and are signed together. |
| `programs-create-01.json` | `6877abcbe220a4d373e08b79a6b6afab28853795be58b71330513ab8099469cf` | Separate two-container SSA fixture with dedicated socket/ring volumes and pinned package image. |
| `programs-live-01.json` | `fc839afc0d3f24708d7a8d879911286086bfd37fe9595c187a6a6a9e30656326` | Retained pre-load lint failure: test module directory missing from the search path. |
| `programs-live-02.json` | `e550a75ecf9a237651b1eae68d397e492e733bbd6ce101b0e23966016e0d8fd8` | Retained pre-load Tao import failure: runner replaced the inherited protobuf module path. |
| `programs-live-03.json` | `2228fad3d35b925d70c675824196d05bed1abeefc29100bba37923a68d085b51` | Eight phases, 18 exchanges, 594 records; Black/pylint and JSON/Tao reports pass. Separate owners, fresh replacement, negative controls, restored hooks, stable process and zero restarts. |
| `programs-cleanup-01.json` | `ed0ccd03d633ec4021a929115d330e2f3e1f0d1d2fb342e4a2131abbef9d3a86` | Twelve-file archive checked before scoped removal. Both hooks checked again. Fixture containers, networks and volumes removed; toolchain identity/state unchanged. |
| `programs-evidence-20260930.tar.gz` | `13d07e877d1c8677218df8de5c35269d84908edbe3c2fc64aa84e967ea543f9b` | Twelve fixture files: passing result/configurations/Tao records and failed attempt 02 logs. Attempt 01 stopped before a fixture evidence directory was created; its separate receipt is above. |

### Program ownership and TMM build, 2026-09-30

**MEASURED: pinned native/socket tests and linked TMM binary.** Native checks
09 and 10 pass with GCC 13.3.0, clang 18.1.3 and the pinned uBPF/PREVAIL revisions.
They cover two owners with two entries, shared sites, owner-local maps and
configuration, stale controls, rollback, delayed calls, reclamation and bounded
reuse. Both bytecode entries pass PREVAIL. Interpreter/JIT, sanitizer, signed
socket and existing activity/context/trampoline/return-hook checks pass.

The TMM build uses Docker GCC 11.4.0 and top-level `make tmm`. Attempt 01 fails
because the loader did not enable the GNU declaration for `struct ucred`.
Native check 10 repeats the suite after the source fix. It also compiles the
loader without the harness's command-line feature macro. Attempt 02 compiles
TMM successfully, then stops at a faulty name-based trampoline check.
Verification 03 checks the same linked symbol table and exact symbol address
ranges. All twelve trampolines pass. No second compile was needed for that check.

Build ID: `5784e768cc4f5c25993aef7dfb050c54a14042ea`.
Linked ELF SHA-256: `1dcd0231627fc55a25beeba621c225365e929c5100ff156a4c69864d20772966`.
The 203,549,136-byte copy is at
`/home/starin/eob-config-20260925/programs-integration-03/tmm.no_pgo` on the build box.
Protected source/library hashes and container identities agree before and after
verification. The existing HTTP/2 CVE-fix revert remains in this tree.

Witnesses: SELF (test assertions and source comparisons), INDEPENDENT (PREVAIL),
TOOL (compiler, linker, ELF symbols, instructions and globals check).
These receipts cover the linked build. The later package and live test are
[recorded separately](#program-ownership-live-validation-2026-09-30).
Multiworker behavior and data-path cost remain unqualified.
[Contract and commands](substrate/PROGRAMS.md).

| Cached file | SHA-256 | Result |
|---|---|---|
| `programs-check-09.json` | `403c2612ca3b9f22a8b223c9b2ba1e9e24777cadada895478835f8c890d9a09e` | Native/socket suite passes before TMM compilation. |
| `programs-check-10.json` | `7cce91bb5bc202352583f47aedd31b5955eb6d7d6007bc5f1063fb66f9c4d717` | Suite passes with the loader feature-macro fix and added compile check. Exact source snapshots retained. |
| `programs-integration-01.json` | `0138238607da27a079e9afb72a3c83a4c47e970c6ef7a2645f3f628b68e69a7c` | Retained TMM compile failure: incomplete `struct ucred`. Sources and whitelist changes were already applied. |
| `programs-integration-02.json` | `0e840ea30c3d4b4861d6492fe774079c20e2f39bf3468b4ed61af77769513e80` | `make tmm` returns zero. Follow-up check fails because name-filtered objdump emits no instructions for the slot-zero alias. |
| `programs-integration-03.json` | `a7fc77acdff72ee9bcfc1f574ae3a4896df652013c80ca947a244dfcec2bb6f2` | Existing build passes symbol, TLS, twelve trampoline, globals, source and preservation checks. Linked ELF copied and hashed. |

### Combined activity records, 2026-09-30

**MEASURED: ten combined exchanges in the isolated, single-worker HTTP/1 fixture.**
One ELF supplies both entry programs and their explicit exchange key. The run has
80 JSON field records and 184 HTTP-handler records. Three requests reuse one
connection; four concurrent connections use the same message ID. Exact fields,
replay and cleanup pass. Identity remains unknown. HTTP/2, pipelining, multiple
workers, silent missed hooks and sustained data-path cost remain unqualified.
Witnesses: TOOL (source/layout/compiler), INDEPENDENT (PREVAIL), SELF
(native/live fields and exporter checks), KERNEL (hook bytes and process state).
[Contract, commands and limits](env/ai-traffic/ACTIVITY-COMBINED.md).

Live attempt 03 uses the corrected discard handling. The later exporter check 02
adds an explicit reply-before-header-confirmation check and replays that same
measured journal through the current exporter and real Unix-socket API.

The timestamp follow-up replays the same journal with UTC source-observation
timestamps and monotonic elapsed time. Eight exporter/API tests pass on the build
box. SELF witness: exact comparisons with saved raw records, clock/missing-time
mutations and replay checks. This is not a new live traffic run.

| Cached file | SHA-256 | Result |
|---|---|---|
| `activity-group-discovery-01.json` | `137a8e904a2e082067166eea63ecf753de497e092e03eb4d8a5cd9f3c8403f3e` | Source and runtime layouts. |
| `activity-group-check-01.json` | `55a797e7af8659a6830bc0759710219aafb098adaa5fa60d5ad1b1b7f98cda48` | Macro redefinition refused. |
| `activity-group-check-02.json` | `cdb358e55f2f95a01379229802333e627a5cc0a4fb51239be0f46681a3db5269` | Stack limit refused. |
| `activity-group-check-03.json` | `a9df8f9a3a12bf04308d70949fddef1e098a880c0c48edc48d0489d9308c10b1` | PREVAIL passed; native loader refused a jump. |
| `activity-group-check-04.json` | `992fa5073c9b2f908ef924e572ceef421bdebe639335e0ff3da94ae30f9df7ba` | Function sections: pinned PREVAIL, interpreter and JIT passed. |
| `activity-group-live-01.json` | `ccc391cc4cc99f179adef84c37b220a8809625ee9986c4e3ff36017cc9bffc19` | Failed: no combined records. Client JSON precedes the AIMCP request-header event; request flags also reject the response-only test. |
| `activity-group-check-05.json` | `ac68e9bff48e0d55d3c23bfa95564929d5b5a12ad38a75a6055610b75cca41e5` | Failed capacity assertion: the host HASH evicts on full instead of refusing admission. |
| `activity-group-check-06.json` | `9fa6ed59191b3819e114c7eeba5e237d93d1028153dd2eefd29542d4259252dd` | ABI 2 passes both pinned PREVAIL entries and GCC/clang interpreter/JIT tests. Reserved admission counter, zero map evictions, release/reuse and target-parser checks pass. Signed ELF: 182,056 bytes. |
| `activity-group-create-01.json` | `bf3ddd6d602dfc0aa6ecf7e72fbd4ce3a468d597ce94b4072ca933b708400f77` | Isolated fixture creation with collector mounts and recorded image identities. |
| `activity-group-live-02.json` | `2f6dfe9ea8771173dc98f3f801bc0dcf756cfe8bb082770b0dff0600c3273503` | Failed exporter assertion: ring wrap-padding DISCARD incorrectly flushed a pending group. Bytecode emitted the new keys. |
| `activity-group-live-03.json` | `f28d16847e4fcda84742933124c9097cad1e5996fa0d8d110f272da6d1f63b3f` | Ten combined exchanges, exact traffic/fields, counter deltas, second-cursor and single-row-page replay pass. Both hook patches/restorations observed; process unchanged, zero restarts. |
| `activity-combine-check-01.json` | `770879bf54a7e7823a52427a764407414e5cd38ac183a14eb5d76b2a8d301c3c` | Five saved-journal/exporter/API tests pass after discard handling correction, using live attempt 02. |
| `activity-combine-check-02.json` | `a98b1db0b6b7e7b71140e4f1113a6dac8e56547d93a821449b0db095c82c0dfd` | Six current-exporter tests pass on live attempt 03: page boundaries, 38 missing-record/discard mutations, producer/key/field mutations, bounded state and journal/socket equivalence. Includes ten measured combined examples and source snapshots. |
| `activity-timestamps-check-01.json` | `d0e1dcadc04fd862e539e7fccc88bcd5f4cdf80b9f9620f1b671c9a2539785f6` | Eight exporter/API tests pass. Ten replayed exchanges now retain nanosecond UTC start/end/last-observed timestamps and monotonic duration. Missing/invalid time, unfinished exchanges and clock adjustments tested; source snapshots and examples retained. |
| `activity-group-cleanup-01.json` | `765a8048aa7645cfafe36c99712d96be9ae67a2394599ba1451bca8d8b9a7760` | Archive checked before scoped removal. Hook bytes restored; retained programs disabled. Fixture containers, networks and volumes removed; unrelated toolchain container unchanged. |
| `activity-group-evidence-20260930.tar.gz` | `a9bcf4b9ca570aa1cb88fcce7e200518b6ae6d65f471b2ab97297e96601d1e46` | 24 checked files from all three live attempts, including journals, failed/passing results and Tao output. |

### Agent activity export, 2026-09-30

**MEASURED: archived-record replay and collector API tests.** The versioned JSON
exporter maps 468 metadata records from five saved live journals. It keeps all
478 journal rows, including source/health diagnostics, and preserves replay cursors.
Six tests pass on the build box. They cover the existing Unix-socket replay API,
retention errors, raw/truncated strings, exact numeric IDs, gaps and malformed
records. Injected identity/trace claims do not become bindings. SELF: exporter
and tests. This is not a new TMM run or authenticated agent attribution.
Identity and correlation remain unknown; program bindings are not verified by
the exporter. [Format and commands](env/ai-traffic/AGENT-ACTIVITY.md).

The first local check assumed one journal per archive; the token-method archive
contains two attempts. The test now selects the passing run's journal. Both local
checks also stopped when this workspace rejected socket `chmod` with `EINVAL`.
The same API test passes on the build box without changing the collector.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Retained first archive-selection and socket-startup test failures / local session | `activity-export-check-01.json` | `1e49fa476315a5943ef22334c3813eb43c919e2e196ea6b3d841c26606480537` |
| Archived replay passes; socket chmod failure retained / local session | `activity-export-check-02.json` | `fd7df707920428aeaaf843742875e69f0ea19c94099e549e924cb9f1d2ffd848` |
| Six passing tests, five archive hashes, exact source snapshots and example event / build box | `activity-export-check-03.json` | `a8224446af3475b6a8b8faa72b43cfbbb77b5ba5f1b6f8b999ec53e1f588402a` |
| Six legacy-export regression tests pass after grouped-frame support, with the same 468 metadata and ten diagnostic rows / build box | `activity-export-check-04.json` | `7373b64ec745af5fc143a2faba7e48eb2625f04d2f85565696442e7e60904378` |

### Production entry snapshots, 2026-09-29

**MEASURED native VM tests, TMM build and package. Live admission is refused.** Production return frames
and the production VM pass 78 cases per compiler with GCC 13.3.0 and clang 18.1.3.
These cover interpreter and JIT paths, two return-register values, nesting,
capacity, skipped returns, failed capture, replacement and mode changes.
PREVAIL accepts the test programs at a 256-byte stack limit. The old target parser
refuses the new signed target version. Ordinary return/context regressions pass.
SELF: programs, target fixture, output sink and assertions. TOOL: compilers and
source capture. INDEPENDENT: PREVAIL. No live initialization result is claimed.
[Contract](env/ai-traffic/ENTRY-SNAPSHOT.md).

The JSON program passes 22 native cases in each execution mode and strict PREVAIL.
The packaged image is build `7bbb06a0…`. Requalification checks the JSON source,
layout and compiled initialization path. Binding then refuses unwind imports.
Full-width `readelf` output finds `_Unwind_Resume`, `__cxa_begin_catch` and
`__cxa_rethrow` in both this image and the previous `ca69b84f…` image. Shortened
output hides all three from the old gate. Its zero-import conclusion is
**FALSIFIED**. Corrected ordinary admission refuses both binaries; native positive
controls and failed-tool tests pass. The isolated fixture was removed after
archiving the refusal. Its hook stayed unchanged and all slots had zero fires.
TOOL: binary inspection; SELF: admission checks; KERNEL: cleanup witnesses.
No live initialization program was loaded. See `CONTESTED-PREMISES.md` §39.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Tracing-context write preflight / pinned build box | `entry-snapshot-preflight-01.json` | `349d5516a3e0ae3554da2fba505e93dbac5a7f7c94633c2a7023523ddc56c43a` |
| Retained native link failure: omitted relocation module / build box | `entry-snapshot-build-01.json` | `ccd5e2dcf5aa41370ba263fb47a30fb7e15517c99b0fe117bb86bbcd8f54bddf` |
| Passing production VM, return-frame, admission and target-parser tests / build box | `entry-snapshot-build-02.json` | `ae34e5c82afd93e325b6bea0b99b78b81ce9a0ad0cdc826503bfc1e82426b43b` |
| Toolchain TMM build and protected-file checks / build box | `entry-snapshot-integration-01.json` | `2c89b2fd8163b1a9212360c6a0187e1ed84d48119a094db891ddb5e59f1d1d9d` |
| Package and image gates / build box | `entry-snapshot-package-01.json` | `92082a158f1688e6f2336b8d41c9a0189aead553bff17e9c80cd41290e59bb87` |
| JSON bytecode: PREVAIL and 44 native cases / build box | `json-initialization-program-01.json` | `f8e599689561bda615d9b8e03bbcfd4c9653cb906760650eaaff8f5fc0ba1b0d` |
| New-build source/layout/instruction checks; binding refused / build box | `json-initialization-program-02.json` | `61b2c4fb32e9f4f7099e9eeb23a06756b0fd4d6f241a59ddbe19e80ec265be20` |
| Isolated snapshot fixture creation / build box | `json-initialization-create-01.json` | `823bcd50d5346cecea48cd66bce91d47d1bbaaf35e991daaa7d3907da011260f` |
| Refusal archive and scoped fixture removal / build box | `json-initialization-cleanup-01.json` | `0d6d7a98c54c45f44c895b4a4d2392d5c361059dbbac86051d83e8c57dfeed42` |
| Archived refusal; no live program loaded / isolated fixture | `json-initialization-blocked-evidence-01.tar.gz` | `7520b1331236723cb9cda72a0a55d356901ecf0ce8297118891ce78a90e9de7c` |
| Full-width versus shortened imports on both pinned binaries / build box | `snapshot-unwind-audit-01.json` | `a175f23a05c7ec26bb5e60ec7a4d4333e8248775331c76edd1cfb24d1c81685c` |
| Corrected admission, positive controls and failed tools / build box | `snapshot-unwind-check-01.json` | `85a7f9c8c8572af9aa30b6ea91d1d5f0ca5b4c79d01ca2eac45d281bd87eacfb` |
| Saved-evidence check: 69 source snapshots, 44 JSON records, 13 decoder refusals / build box | `entry-snapshot-check-01.json` | `f9eac7d98bfaf8a0a160029bfff9b7ec648ad5f8433bd9d28cc8320427e5c6f8` |
| Failed program prerequisite retained before any live command / build box | `json-initialization-live-preflight-02.json` | `fc6ea889770eef7a9a70f275de808cd1bf883287947b927fcce70d11430e3a9d` |
| Authored record of prerequisite and local-verifier stops / session tool output, SELF | `entry-snapshot-session-01.json` | `907a4c5ebaf9ffba468c8ea201753926f915271911ab6233622bd5de7d78d02e` |

### Void-return completion test, 2026-09-29

**MEASURED native fixture only.** GCC 13.3.0 and clang 18.1.3 each pass 24 cases
and 1,100 observed returns. The real entry trampoline, shadow stack and return
stub run with a test entry-snapshot adapter and native program stand-in. Ordinary
return hooks and the 96-byte context contract also pass. The real TMM JSON handler,
production entry capture and live lifecycle are not validated. SELF: fixture and
assertions. TOOL: compilers and source capture.
[Contract and results](env/ai-traffic/VOID-COMPLETION.md). Files are in `evidence/cache/`.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Retained nonexistent-header source-capture stop / build box | `void-completion-build-01.json` | `2cae2546c1e2d9559bd71b04efcca51190d37133764df611b6c9a283e4f49bbc` |
| Passing two-compiler native test and return/context regressions / build box | `void-completion-build-02.json` | `05d7cbaf045180bb43a66a3e2c56ee362b3f54a11a8c01e1d5b6247ebc16a09e` |
| Passing saved-evidence check, 19 source snapshots / build box | `void-completion-check-01.json` | `c7b82d2aa5bfe812d4c7144f8e3b15b5d5ce70682fcc00e77d4694933d0a9e78` |
| Authored summary of source-list and verifier stops / session tool output, SELF | `void-completion-preflight-01.json` | `8bd2f878f98ff385d1438f8f2aece6926e411d6f7c96de68ff79f63510504da1` |

### JSON initialization-completion qualification, 2026-09-29

**MEASURED source, compiled-code and admission checks only.** Two captures refuse
the handler and reset return hooks for void return types. The enum-return control
is admitted. Initialization helpers have no standalone entries. The compiled
forwarding path shares a disabled bypass and calls the next node's handler.
None of the tested candidates qualifies as an initialization-completion witness.
No live probe was run. TOOL: captured source, debug, symbols and instructions.
SELF: admission policy and saved-evidence verifier.
[Contract and decisions](env/ai-traffic/JSON-INITIALIZATION.md).
Files are in `evidence/cache/`.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Registered contract, pinned source, two return refusals and admitted control / build box | `json-initialization-discovery-01.json` | `dfbb050dd97fc300d9cc5fc8beba043625666d4fccc8f315b9a431f854b8e7e5` |
| Repeated admission, complete handler range, initialization jump table and xbuf binding refusal / build box | `json-initialization-discovery-02.json` | `787a96e8d860640f509a4143ff380530ef2708ad3ee01e16c24c9699c7c6b2f0` |
| Passing verifier: 48 source snapshots, seven source references and 15 instruction locations / build box | `json-initialization-check-01.json` | `438f0727527f69ebbd7fc1e4aa75e18e0a02510ea6fa18526ef5a05953a34c97` |
| Authored summary of symptom lookups, capture refinement and partial-copy recovery / session tool output, SELF | `json-initialization-preflight-01.json` | `ba022ee34a4b8191eff85c2f2332c4f241af957bfcb89aabc2c4998475586851` |

### JSON-context boundary observations, 2026-09-29

**MEASURED, bounded one-worker fixture.** Three entry probes observe handler,
completion and reset calls. Live 02 has 13 exact HTTP exchanges and 306 records.
Eleven records have no qualified context fields. The consumer therefore rejects
the full window. Storage tags remain observations, not lifecycle or request IDs.
SELF: fixtures, native checks, records, counters and replay. INDEPENDENT: PREVAIL.
KERNEL: process and hook bytes. TOOL: source, layouts and container state.
[Contract and results](env/ai-traffic/JSON-LIFECYCLE.md). Files are in `evidence/cache/`.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Pinned source, event constants, debug layout and compiled paths / build box | `json-lifecycle-discovery-01.json` | `bea20f4ae1fba8feef7a1688bcfa3996fcccae570cccfbb8339bcad62e088889` |
| Retained unused-helper compiler failure / build box | `json-lifecycle-build-01.json` | `3268d8533ee09bab2a8c2ec77e15ca66aa2142f123db4ed84989d0ce88aa9c53` |
| First passing three-program PREVAIL and 312 native records / build box | `json-lifecycle-build-02.json` | `749fdff763922b0a8aedd20793a8e8d1df13044ce5e8309267433d2fb6246d63` |
| Passing build with stricter consumer source checks / build box | `json-lifecycle-build-03.json` | `4499da7c9a09773f01c107ef1006de4c88ffb7e3e79ae0d1da1e1f89a6e72352` |
| First isolated fixture creation / build box | `json-lifecycle-create-01.json` | `94d14c51118703c0732eba75181c1a9f632fa1ff0c8ca2238052698c5262cad1` |
| Retained unavailable-state assertion and restored hooks / isolated fixture | `json-lifecycle-live-01.json` | `0da67c6ab7730f51290e20ed30d3307197b6302e7a8b74999bdbac9f56dff9e1` |
| Failed-run archive and scoped removal / build box | `json-lifecycle-reset-01.json` | `708d971b611b116a43957954dc8f0eb86423747659fbedb6e8146749be8bc90e` |
| Nine failed-run evidence files / isolated fixture | `json-lifecycle-failed-evidence-01.tar.gz` | `d284c8f35f13dad2f5918cbd5fc966355687aba6a19ffc68952b4aa52a2d91a1` |
| Fresh isolated fixture with collector mount / build box | `json-lifecycle-create-02.json` | `6ef1e0e4808d09e255deee67f194a40f9ae6dd07b093470a70976c1793baad10` |
| 13 exchanges, 306 boundary records, replay and three kernel witnesses / isolated fixture | `json-lifecycle-live-02.json` | `333b783145f5db506bdb0744d1f0eaf59b95c38a65a4523da4e8a08ec232ff59` |
| Restored hooks, all slots inactive, archive and scoped removal / build box | `json-lifecycle-cleanup-01.json` | `9d6b947a5f068021dc64dd20f3e130742db4ed6e1537e3e7a14048a1e95f8600` |
| Nine passing-run evidence files, including the journal / isolated fixture | `json-lifecycle-evidence-01.tar.gz` | `5ee964447821303138fa9f9ff43018cb8c3197b3611a762e798562ca830d071d` |
| Authored summary of test-wrapper stops and symptom lookups / captured tool output, SELF | `json-lifecycle-preflight-01.json` | `d4d966bf522a05180c616ce105a94fd2084917fe632f6b1f4dbdb985b6e8d1a5` |
| Retained saved-evidence check failure: hook-change rows omit process `stat` / build box | `json-lifecycle-check-01.json` | `26b67b4389b582fe980f627a6de6aa897557ce0424e0d0d7e7c9b7eb0bde32c2` |
| Passing saved-evidence check: 125 source snapshots, 14 decoder rejections, native/live records and archives / build box | `json-lifecycle-check-02.json` | `3e3de515a2e12db248649cd6a639ece3ee92a89047b978b8d4720af281289092` |

### Message ID and flow side, 2026-09-29

**MEASURED, bounded one-worker fixture.** One record contains the literal message
ID and the observed connection-flow side. Build 01 passes pinned PREVAIL and 224
native invocations. Live 01 has 44 exact exchanges and 88 records. These include
reused IDs on one client connection and equal IDs on four concurrent connections.
The result establishes field extraction, not message role, common lifetime or
request/reply association. SELF: fields, fixtures, counters and replay.
INDEPENDENT: PREVAIL. KERNEL: process and hook bytes. TOOL: source/container checks.
[Contract and results](env/ai-traffic/ID-FLOW.md). Files are in `evidence/cache/`.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Registered contract, pinned build, PREVAIL and 224 native invocations / build box | `id-flow-build-01.json` | `39161b7bff14c1bed1db12fd8fb23444116a19e63e5bc2769355a5de6e9d07b6` |
| Isolated fixture creation with collector mounts / build box | `id-flow-create-01.json` | `7bef2238908a64e1694c45af1621fc34ec32d7f3c36f28addbd82ea8a55e85f8` |
| 44 exchanges, 88 same-record ID/side observations and kernel witnesses / isolated fixture | `id-flow-live-01.json` | `22db1a2a4459a5de9231036fea658b198e41ffc86de4611a7220bd60bf468727` |
| Restored hook, inactive slots, archive and scoped removal / build box | `id-flow-cleanup-01.json` | `4804ea202f17ea5f4f3efe55b75c87491515f0d7a4e5efe11641d4ac60226142` |
| Seven live evidence files, including the 90-event journal / isolated fixture | `id-flow-evidence-01.tar.gz` | `4636f9a7e6e2f069637c079dbae6037586bbc25864eaf82c5be1004a3fd3d2e8` |
| Saved-evidence verification, 54 source snapshots and 12 decoder rejections / build box | `id-flow-check-01.json` | `09af1da3bce7c4673c9f550c26ee670f73a92e650af3f335a558da164c08ca6c` |
| Authored summary of formatting and missing-import stops / captured tool output, SELF | `id-flow-preflight-01.json` | `0e78ffb2a04981c1d96a2f3803d9b3f1a98477226cd3f04188d62613fb8a35dd` |

### Message scope qualification, 2026-09-29

**MEASURED source and compiled-code inspection only.** The pinned JSON completion
path uses flow-side state. Its context is reused between messages and has both
connection and stream storage forms. Source and compiled reset/handler paths are
checked. Runtime lifecycle, a common request/reply lifetime and message association
remain unvalidated. TOOL: source, debug and instruction capture. SELF: qualification
checks. [Contract and candidate decision](env/ai-traffic/MESSAGE-SCOPE.md).
Files are in `evidence/cache/`.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Initial JSON-filter source, layout, binary and hook capture / build box | `message-scope-discovery-01.json` | `abb4e381aa9ed768d73760c6801ea89998469de3adab14a6aa290ad0606024d5` |
| Added flow-side definitions, stream/node sources and complete handler ranges; 16 embedded files / build box | `message-scope-discovery-02.json` | `80baa9981872c732936054ae9ca6f51a38fb89148ec9f02bce2916f3d3efa1a3` |
| Passing pinned qualification with source references, 11 instruction checks, candidate decisions and verifier source / build box | `message-scope-check-01.json` | `12bac7f33221b3d72b7767202faa8af56d9bcb1af16b500a75b0277c797f13be` |

### Observed message IDs, 2026-09-29

**MEASURED, bounded one-worker fixture.** Literal root IDs retain type and raw
bytes. Numeric values are not converted or rounded. Missing, null, duplicate and
incomplete IDs do not establish matching keys. This result does not establish
request/reply association or trusted caller identity.
SELF: fixtures, values, counters and replay. INDEPENDENT: PREVAIL.
KERNEL: process/hook bytes. TOOL: source and container inspection.
[Contract and results](env/ai-traffic/MESSAGE-ID.md). Files are in `evidence/cache/`.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Rechecked source, layout and compiled JSON-cache path / build box | `message-id-discovery-01-base.json` | `0c79f3bb14fddc567db25f41333acdc94b9ae371009274266bf39ad2588da70e` |
| Registered ID field contract and discovery binding / build box | `message-id-discovery-01.json` | `88a3b4128b468d5189a5eff53a9296b071da6b89e5b54db94a85d350e9e1e734` |
| Pinned PREVAIL at 256 bytes and 194 native invocations / build box | `message-id-build-01.json` | `c2826afbbccdd95fa92a73fbb9827f64dca503bbae43094b09a93eb8740c5a8e` |
| Isolated fixture creation with the collector layer / build box | `message-id-create-01.json` | `18a4528ee6eaadfd233c677821c5e3f6c2eb3ecc6bda07d6329c358042a46954` |
| 35 exact exchanges, 70 ID records, journal/replay and kernel witnesses / isolated fixture | `message-id-live-01.json` | `94439d801e899c64ca21a173920e4b35b50ec7ea73dcef164647d503968024e3` |
| Restored hook, inactive slots, seven-file archive and scoped removal / build box | `message-id-cleanup-01.json` | `63221c42d9a9a8039d5cc9f60f88754e433af45d2a4c0f95e65fc07ae19ab66b` |
| Live reports and 72-event SQLite journal / isolated fixture | `message-id-evidence-01.tar.gz` | `520a7f2251b407350784db65a7342962c4d23702a1c36685374bffac550fd919` |

### Reported reply fields, 2026-09-29

**MEASURED, bounded one-worker fixture.** Literal result/error presence, signed
integer error codes and Boolean tool-error reports. These are reported fields,
not proof of remote success, authenticated identity or request association.
SELF: authored fixtures, values, counters and replay. INDEPENDENT: PREVAIL.
KERNEL: process and hook bytes. TOOL: source and container inspection.
[Contract, results and retained failures](env/ai-traffic/REPLY-METADATA.md).
Files below are in `evidence/cache/`.

| Evidence / origin | Cached file | SHA-256 |
|---|---|---|
| Rechecked JSON cache source, layouts and compiled path / build box | `reply-metadata-discovery-01-base.json` | `0c79f3bb14fddc567db25f41333acdc94b9ae371009274266bf39ad2588da70e` |
| Registered field contract and discovery binding / build box | `reply-metadata-discovery-01.json` | `0adb9aeacf2c3d84e0ee27f46b9e413adb61f4fc50867d0d12e42ff59991ea0f` |
| First pinned PREVAIL and 106 native checks / build box | `reply-metadata-build-01.json` | `206259091659faaab2ff33a3a07fac15fc06df990f025030b9f27776e2f8ee70` |
| Build report compatibility and case formatting update; checks pass / build box | `reply-metadata-build-02.json` | `4a0849d712c14fc1aee403a799a8cad86821011aa8f9fbf3976a4c1d0c7cc56d` |
| Final fixture formatting; pinned PREVAIL and 106 native checks / build box | `reply-metadata-build-03.json` | `ba935d09a6457e5c1de161fe766db072b387e4cd03328a360370eca619263f3b` |
| Initial creation omitted collector mount layer / build box | `reply-metadata-create-01.json` | `133167771b9c84ef54545672a763fa06b059120e89248fd1aa991e69434da5c3` |
| Collector API unavailable before probe load / isolated fixture | `reply-metadata-live-01.json` | `2d98f1016dc26a5b3613e95b976d3171b2b4820efddf60682736da7066bff98d` |
| Missing read-only API mount checked and repaired / build box | `reply-metadata-mount-repair-01.json` | `654335576fc1c497e479326fd102a6668cacb4744845a0974b1437ea17577a65` |
| Configuration wait timeout before probe load / isolated fixture | `reply-metadata-live-02.json` | `b38667b44c9d1b0bf8bca66ba84ece47880f18bc00b863e3427214167690c30e` |
| Reset check expected hash in a final witness row; stopped / build box | `reply-metadata-reset-01.json` | `ab44504ef18619ef3bf1a3f71a03648c4528a73c4ac1f5d44e6044f519f7b0e6` |
| Reset check matched a source-code guard string; stopped / build box | `reply-metadata-reset-02.json` | `e617f86177c94e667accd060a30e44c72f845735c88ae9ec85c6f53f29293ed2` |
| Eight-file failure archive checked before scoped removal / build box | `reply-metadata-reset-03.json` | `ca64fa9aa4ee796be3d380e1e5a059899ab8fe6e40dd949822ca190003a54a20` |
| Saved pre-arm failures and journals / isolated fixture | `reply-metadata-failed-evidence-01.tar.gz` | `346a58aac030f7b1fd507d51c8c296849558dfd462f07d23a1317fad842af5e3` |
| Fresh creation with collector mount layer / build box | `reply-metadata-create-02.json` | `ad1e3e5da0d2d6b0641fe36b1cb836872f35853e090728bcba67c1ab2c9e9152` |
| 38 exact exchanges, 76 field records, journal/replay and kernel witnesses / isolated fixture | `reply-metadata-live-03.json` | `955af1f0a649a9e0311c38e133b7508f9d290ec4dfe91c0391d67e3505bb1e18` |
| Seven-file archive, restored hook, inactive slots and scoped removal / build box | `reply-metadata-cleanup-01.json` | `05da4b4f93deb34122f1b8ab4291cad5669edf845d95177d21bc53b8215a32f5` |
| Successful live reports and SQLite journal / isolated fixture | `reply-metadata-evidence-01.tar.gz` | `70df07753ff3a3d086d9c62e94553d37220b68778519e0993cfd54d15c1c64d6` |

### Requested operation targets, 2026-09-29

**MEASURED bounded tool-name and resource-URI extraction.** The pinned build
passes PREVAIL and 74 native invocations. The isolated live gate passes 28 cases.
These are requested targets, not proof of authorization or successful access.
Values/tests are SELF; PREVAIL is INDEPENDENT; hook/process checks are KERNEL.
[Contract and results](env/ai-traffic/OPERATION-TARGET.md).

| Evidence / source | Cached file in `evidence/cache/` | SHA-256 |
|---|---|---|
| Rechecked source, debug layouts and compiled JSON-completion path / build box | `operation-target-discovery-01-base.json` | `0c79f3bb14fddc567db25f41333acdc94b9ae371009274266bf39ad2588da70e` |
| Registered target contract and bound discovery receipt / build box | `operation-target-discovery-01.json` | `340169f3446d1253b1cf5f05cbcd298e934e41a025a8735b9cf666f33da88d3c` |
| Pinned PREVAIL at 256 bytes; 74 native interpreter/JIT invocations / build box | `operation-target-build-01.json` | `3d68bc32307b55fd3879ed71c1a27df769329416f3c7d3b20f3810e254671459` |
| Isolated fixture creation and other container inventory / build box | `operation-target-create-01.json` | `273cf014a3cb6fbd00881c49348b2339bdb54d2050f6406b269db05d78b16929` |
| Exact target bytes, explicit exclusions and replay across 28 cases / isolated fixture | `operation-target-live-01.json` | `97d61b045175d1ab71dff708e8e5efc21ba1d74ac9232312c6d64e6daa661a81` |
| Restored hook, inactive slots, checked archive and fixture removal / build box | `operation-target-cleanup-01.json` | `c64dc5993c30728dbbfd95efd76b27049406d7001cf9b3158fe835815145d67e` |
| Live reports and SQLite journal / isolated fixture | `operation-target-evidence-01.tar.gz` | `475591fb9b936c0dae2710c8b3d3b248208fe0d79d0f78f87f17bfeb837edcca` |

### Response metadata qualification, 2026-09-29

**MEASURED bounded response-status and local transfer-completion extraction.**
Live attempt 02 passes nine isolated fixture cases. Values and comparisons are
SELF; PREVAIL is INDEPENDENT; hook/process checks are KERNEL witnesses. Local
status and done arguments do not establish remote-operation success.
[Registered contract and results](env/ai-traffic/RESPONSE-METADATA.md).

| Evidence / source | Cached file in `evidence/cache/` | SHA-256 |
|---|---|---|
| AIMCP/HTTP/JSON/SSE and proxy source; pinned binary, handler disassembly, status offsets and event values / build box | `response-metadata-discovery-01.json` | `3cd1175de563e84a9601aec6063681abd854eb7d63b1e01bdb11ae5c232ecbdf` |
| Pinned PREVAIL at 256 bytes and 80 interpreter/JIT invocations; exact status/done fields, invalid state, guarded reads, output refusal, sequence saturation and instance replacement / build box | `response-metadata-build-01.json` | `1b07e162408928d488ab8f2810ff07940958227810fe9eb33cabff7720152d10` |
| Isolated fixture creation and other container inventory / build box | `response-metadata-create-01.json` | `c30e3b8e17adcaf77d66acba8fd39a8f4269424df22504731daf62d5d2a43b9a` |
| Attempt 01 rejects normal HTTP 200 as out of scope; hook restored / isolated fixture | `response-metadata-live-01.json` | `6e62d2df04cf41d527265f429b56df87fd83926cffc4f6844215a0840d130ec8` |
| Cache-flag correction: HTTP/2 serializer source and compiled status accessor / build box | `response-metadata-discovery-02.json` | `42e8a5047f613ef9f29d9858d7042db9e3c0fd1c65b1412110d86dc569c32c45` |
| Build 02 stops before compilation: reversed request/trailer names in layout assertion / build box | `response-metadata-build-02.json` | `b7443d94330a680c5f185da26317f834b43bf3ee6be9cc1a4fb1ee989038e4a8` |
| Corrected cache semantics and layout assertion; pinned PREVAIL and 80 native invocations / build box | `response-metadata-build-03.json` | `0f70b542151709c8e2684bb08963240e1c28522e8328ca6ab7476937a0d94441` |
| Attempt 02 passes nine cases, including paced, chunked, event-stream and interrupted responses / isolated fixture | `response-metadata-live-02.json` | `7d891d65dc52e690d34ff31d7ddc638f8c6ed1b1472509dfca08d8f432aa110a` |
| Restored hook, inactive slots, checked archive and isolated fixture removal / build box | `response-metadata-cleanup-01.json` | `2d7b75c9f1beffe4b11c69634e35b73cb92caf83a08196feae0984eeb3426d92` |
| Both live attempts, reports and SQLite journals / isolated fixture | `response-metadata-evidence-01.tar.gz` | `8fdcae0f7b981f54a4d81840d14e1f9c0a49060ae67a1b1e2a4965ad3f4ce159` |

### Session and routing qualification, 2026-09-29

**MEASURED bounded session-header and selected-route extraction.** The prepared
build box supplied source, layouts, disassembly and native verification. Live
attempt 04 passes the isolated fixture gate. Values and comparisons are SELF;
PREVAIL is INDEPENDENT; hook/process checks are KERNEL witnesses. Identity profiles
and blast-radius assessment remain IDEA consumer goals.
[Registered contract](env/ai-traffic/SESSION-ROUTING.md).

| Evidence / source | Cached file in `evidence/cache/` | SHA-256 |
|---|---|---|
| Initial AIMCP source, clone entries and field layouts / pinned build box | `session-routing-discovery-01.json` | `ee48a827e7e172abb4fd99840f7f02bb6dcd5613defaf6d8c0b0ffc22c7b9198` |
| Registered header/selected-route limits, connection-flow and pool offsets / pinned build box | `session-routing-discovery-02.json` | `34a6e9b9cad7206e0438722e8b868919dc251c5a4f7343a7122f9a7ad24da357` |
| Session and route programs: pinned PREVAIL at 256 bytes; 34 session and 38 route native records / build box | `session-routing-build-01.json` | `1be02535690d620026978f0ac25671962961bb2c883bea747b870437383f1a1f` |
| Failed first live run: shared state-map name resets per-program sequences; restored hooks / isolated fixture | `session-routing-live-01.json` | `5904b0ff5fa1e6edc052ebe5eba513b0c4320f9b34fa1c6319a5b12e956f8b3c` |
| Separate state-map names; pinned verification, 72 individual and eight interleaved native invocations / build box | `session-routing-build-02.json` | `025e8c91bf2bb0df51debccc2c63bbe613984f8aa48d0d005a27a7a2108fb1f6` |
| Isolated fixture creation and other container inventory / build box | `session-routing-create-01.json` | `2c958ef14754e886e25a8232cbaeaca4a95c7ecfa029f4d36e130a569d8bd424` |
| Attempt 02 stops before loading: retained journal contradicts empty-history assumption / isolated fixture | `session-routing-live-02.json` | `2fcc97fef8e7a3c945013e44ef2331758130a200ba0eefd133563c996c8929a3` |
| Attempt 03 stops on replay JSON decoding after partial exact-value comparisons; HTTP status not captured / isolated fixture | `session-routing-live-03.json` | `4c2b2535c6784e1292dce21822327cbba6321f1fca725e516c6dca54dae26046` |
| Attempt 04 passes: seven requests, five session-header records, seven selected-route records and replay / isolated fixture | `session-routing-live-04.json` | `440d7232b497fef22d99937be1d87ee5b1b30579b32ff07caef60f1df87cf6b6` |
| Restored hooks, inactive slots, checked archive and isolated fixture removal / build box | `session-routing-cleanup-01.json` | `e6d704768a2e3705af85e617ef9b4766d9483d8d47145b83c68bc9fed8ced33e` |
| Four retained live attempts, reports and SQLite journals / isolated fixture | `session-routing-evidence-01.tar.gz` | `920ba558e90c00373c5ec1eb9612dcd71e99dd364f5fc848b0910012e14a09d6` |

### Token-cache method extraction, 2026-09-28

Authoritative source, debug types, binary inspection and native checks ran on
`eob-bnk-build-01`. The live check used that box's isolated SSA/Tao fixture and
the existing separate collector image. Build `ca69b84f…`; no TMM rebuild.
Value comparisons and clients are SELF; PREVAIL is INDEPENDENT; process and hook
bytes are KERNEL witnesses. [Contract, exact values and limits](env/ai-traffic/TOKEN-METHOD.md).

| Evidence / source | Cached file in `evidence/cache/` | SHA-256 |
|---|---|---|
| Initial cache-attachment candidate; source, hook index and debug layouts / build box | `token-method-discovery-01.json` | `668c6a242066887aaa768e53499f7845d9b57c59320d2407d0ba5d5e8a1265c6` |
| Revised completion hook; compiled inline attachment path, caller disassembly and `json_scb` layout / build box | `token-method-discovery-02.json` | `0c79f3bb14fddc567db25f41333acdc94b9ae371009274266bf39ad2588da70e` |
| First build: PREVAIL passes; native fixture compilation stops on signedness warning / build box | `token-method-build-01.json` | `a80b72ed6334ae2c4e88f3c417d26887141e321307a813edc2ce90383b57f3a1` |
| Corrected fixture: 56 interpreter/JIT records / build box | `token-method-build-02.json` | `3f1c368b7c9f97b14e4acf3a8da79a5301bddabce06d19f159dba6d662ce83d6` |
| Added nested/escaped-key tests and ordered token bounds: 64 records / build box | `token-method-build-03.json` | `218720672b4e09d4c3e4f29553df47f7871a490a3781f2afe8c07669588cd7c8` |
| Completion-hook program: pinned PREVAIL, 68 interpreter/JIT records, signed target and exact source text / build box | `token-method-build-04.json` | `2f74b021b90384eecffd36fc4ca8fa07f40b1a85ece6be904985896777532aac` |
| Isolated fixture creation, pinned image and other container inventory / build box | `token-method-create-01.json` | `cded502961992fc0d98edf42523554b4f86a42f5e9ce64fd4e70c14d561e9b1e` |
| Failed first live attempt: forwarded request, zero attachment-helper records, armed/restored pad / build box | `token-method-live-01.json` | `e406758d9859080e6de1b227e9d947630401df2c4a2aecb84029d5c809dbd344` |
| Successful live attempt: 13 AIMCP-path requests, 26 exact/status records, journal replay and kernel witnesses / build box | `token-method-live-02.json` | `dcd59034a8278644bd4259e02018e5a82765131b71b55b66f7bc5580a19ef963` |
| Restored hooks, inactive slots, archive manifest and isolated fixture removal / build box | `token-method-cleanup-01.json` | `b121dcf34776d5026bbbba769062ece85b403ec28adb55026ee476df9081f605` |
| Immutable fixture reports and SQLite journals for both live attempts / build box | `token-method-evidence-01.tar.gz` | `52b4bc6109c9932fc780d982f082b085b9cee106d3000f5bb1a9d1e96896eea3` |

### Separate collector container, 2026-09-28

[Registered checks](env/ai-traffic/COLLECTOR-CONTAINER.md). Test controllers and
assertions are SELF witnesses; process access and container state use kernel and
Docker observations. Source validation is not a claim of strong security isolation.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Native build 04: eleven tests pass, including Unix-socket replay, single API ownership and stale-socket recovery | `collector-build-04-20260928.json` | `e22c0a0c3d2ca2cbf88c72eb677b2090d3e8e1d0c9c7f336b3a45cfaa8e4b73e` |
| Dedicated image build 01: resolved Python base digest, exact sources, checked native binary, Python/SQLite runtime smoke check | `collector-image-01-20260928.json` | `be8d7e61f7f2df8204fd1ee73e7b97fa30fa2ffd6e985e5abf3f18d2d96d1d79` |
| Create isolated TMM and fixture with separate collector volume definitions; other Docker identities/state unchanged | `collector-container-create-01-20260928.json` | `90f568035a2e58c4f9c67388811eb46ac03bca6e3caed6bf5332329dc7427ee4` |
| Live attempt 01 stops before attachment. Reading the pinned TMM executable is denied both without and with `SYS_PTRACE` under the default AppArmor profile | `collector-container-live-01-20260928.json` | `30a3ed71ee67362fc4bf04b7864a3596bed06a1a0a0233f570251c3ab5a5a9c1` |
| Diagnostic: collector profile `docker-default`, TMM `unconfined`. With `SYS_PTRACE` and `apparmor=unconfined`, exact source passes and wrong start time is refused; seccomp filtering and no-new-privileges remain active | `collector-container-diagnostic-01-20260928.json` | `5878bee49a94d0210e88a52acd6e83f1089b13b5c21f39fd91eec8791c2f5319` |
| Image build 02: bounded executable hashing; same tested reader/journal/API; corrected AppArmor deployment setting and explicit RAM/swap/temp-storage limits recorded | `collector-image-02-20260928.json` | `88133fda437ac79784b72ace563d4867606de0ffcb5f22ada8d8c17d3cd9b2da` |
| Live attempt 02 stops before attachment: controller expects `SYS_PTRACE`, Docker reports canonical `CAP_SYS_PTRACE`; capability remains present | `collector-container-live-02-20260928.json` | `c45b16796260e10c80d865623efbb525c142d616e36d1a4e5d647d5939dbca97` |
| Live attempt 03: traffic checks and two collector replacements complete; final controller check incorrectly expects `event_id` on the source-boundary event. Retains all commands, consumer pages and kernel witnesses | `collector-container-live-03-20260928.json` | `497bcc811ec2648b5bc872368144518864fae9dbb9b510d7f3492561b1d5f8a5` |
| Evidence-only recovery: no new traffic. Ten requests, eight exact method records and ten unique journal events; normal stop and SIGKILL each followed by collector replacement. Both requests during outages forward successfully and their queued records are recovered. Two separate consumer containers mount only the read-only API volume and receive identical records. Stable TMM process/container/binary, restored hook and journal integrity; original controller failure retained | `collector-container-recovery-01-20260928.json` | `fd36a9e7934bb4b00387532c62c836dc96e18c6648fe3f5945065730b85401ce` |
| Cleanup rechecks the pinned process/binary, restored hook and all 12 inactive slots, archives evidence, then removes the three-container project and its volumes/networks. Other Docker identities/state stay unchanged | `collector-container-cleanup-01-20260928.json` | `3427594d13f848b061a591259a42e03a2dbcea26c01c0ecfb113b4e6eeb0d797` |
| Nine evidence files, including the SQLite journal and fixture control exchange; all hashes match the volume manifest before removal | `collector-container-evidence-01-20260928.tar.gz` | `b7871d4ed994b6bf6de6c3bb3f395009765cc68bdc206e454664822f4bee9ef3` |

### Continuous metadata collector, 2026-09-28

[Contract and scope](env/ai-traffic/COLLECTOR.md). Native checks use the actual
ring and reader, a controlled source process, and authored assertions (SELF).
Process mappings, file identity and locks are observed through the kernel.
These receipts do not establish power-loss durability or production throughput.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Pinned GCC 13.3.0 build; eight native/process checks pass: old helper consumes before downstream acceptance, pre-ACK replay, post-commit deduplication, reader/writer locks, source replacement, full-ring drops, retention gaps, page-limit rollback, two HTTP consumers and reader exit after parent death. Exact sources and test output retained | `collector-build-01-20260928.json` | `6f45ff2286a6f887d6df1ac59c1ebd03f4e0824d4ab18495b4389b75c053bd86` |
| Build 02: nine checks pass. Adds the real legacy drain writing to `/dev/full`: record consumed, output fails, exit status remains zero. This falsifies its at-least-once comment. Adds clean collector interrupt handling | `collector-build-02-20260928.json` | `0da4d5d88e3c9f7141655addea3d0317d3e57d11d1e7dfc3312f738cfaad54fb` |
| Recreate only the isolated template fixture with the pinned image; other Docker identities/state unchanged | `collector-create-01-20260928.json` | `e36d98605b53b3090295ec5594f9d8e68050ca98d0346d9c1d795c0bc4652606` |
| Live attempt 01 stops before attachment: collector starts before the lazy ring exists; runner also reports a missing test-result directory. Original source and restored hook witness retained | `collector-live-01-20260928.json` | `94397dd8f405574cfc985a94f7f689746676336fb674ed768f6f3acae8f467a1` |
| Exact startup log and direct retry: `ls_stream: invalid segment file`. Diagnostic script and all command results retained | `collector-diagnostic-01-20260928.json` | `44ed6078b0bf8bb1e47be2ff25e786135ff55691838add172b72bc2af570ef90` |
| Build 03: ten checks pass. Adds bounded lazy-segment startup and deadline refusal; retains all crash, storage, output-failure and consumer tests | `collector-build-03-20260928.json` | `f709f44ac91e3c8ea4227dc340d43f78e05ae1230ae408c31d9f23c852282ffa` |
| Live attempt 02: ten requests, eight method records, ten journal events. Both HTTP consumers receive identical bytes/cursors. Six value/prefix comparisons and two status-only records; no reported loss/new VM errors/restart. Collector stopped cleanly; journal integrity check passes. Black and scoped pylint pass; kernel witnesses record the pinned process and restored hook | `collector-live-02-20260928.json` | `7475d7438ea0f3800c526ae67c4ea425bc7c825d9c0c23c3df4dc9060a75f776` |
| Recheck binary/process, restored method hook and all 12 inactive slots; archive evidence and remove only the isolated project. Other Docker identities/state unchanged | `collector-cleanup-01-20260928.json` | `32e15d60b1e8eaa1836d7da7c3cdac3f817caa24df6046e9f9e13e227dcdd1ba` |
| Eight evidence files, including the committed SQLite journal; file hashes match the pre-removal volume manifest | `collector-evidence-01-20260928.tar.gz` | `c5a040ab67658e4838e109041e1195365ccae4b1169d6495fe20d75c01ad0f93` |

### Controlled correlation gaps, 2026-09-28

[Registered contract and results](env/ai-traffic/GAPS.md). These tests cover
controller-reported gaps and bounded tracking capacity. They do not establish
detection of silent, unreported gaps. Native traces and assertions, the controller,
client, authority and program counters are SELF witnesses. PREVAIL is INDEPENDENT;
process identity and patch bytes are KERNEL witnesses.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Four pinned signed programs rechecked with PREVAIL. Four-VM interpreter/JIT tests reproduce stale intervals after omitted boundaries, check limits 127/128 and 256/257, and verify fresh reset. Seven guard checks per execution mode; exact sources, native traces and original contract retained | `gap-build-01-20260928.json` | `167d8faca0b9486d493f2c83db1b15e84cab19b08e481190507c4c6dbdf51004` |
| Recreate only the isolated template fixture; pinned image and unchanged toolchain container | `gap-create-01-20260928.json` | `f6a2fddea941d38c63603b7584bb731a47cab0c11184eeb8311035740d972260` |
| Retained attempt 01: lint flags unspecified file encoding; stops before hook attachment and creates no fixture result directory | `gap-live-01-20260928.json` | `cdec703a8b698f5ffbd2662cde055585dd5e0930612a02f574632f323a1ad2dd` |
| Live attempt 02: five windows, 150 accepted HTTP requests, 1,023 calls/records. Known gaps and exhausted capacity stay unknown. Fresh recovery gives two matches and leaves a retained connection unknown. Live stale interval reuse is observed; the old consumer already refuses that live window. Stable process, zero restarts/drops/new errors/selections, all four sites restored; Black and scoped lint pass | `gap-live-02-20260928.json` | `dbb4a888473b1503ece115a13ac7605585483d3c52b6d4523777304fe312a644` |
| Exact live sources and syntax checks pass; final four slots disabled and configuration status refused; final-check sources and scoped lint result retained | `gap-snapshot-01-20260928.json` | `493793d8446807a5a6959acb6ec9036942e7a219cdcf45a08dbf0c26c8496914` |
| All four restored sites and 12 inactive slots checked against the same process/binary; evidence archived, fixture removed, toolchain identity/state preserved | `gap-cleanup-01-20260928.json` | `7eb5e03de63d1c4ff7de28dbeeb2929dbccf33f483ea979ffb042fbe49413295` |
| 25 fixture evidence files, with hashes checked against the source volume before removal | `gap-evidence-01-20260928.tar.gz` | `ab817ba3ef58b6d129513c286ccb42bde647ddd86ec61268b7e32065e8dcece5` |

### Bounded request correlation, 2026-09-28

[Registered contract and result](env/ai-traffic/CORRELATION.md). The final live
receipt includes the pre-run contract, exact sources, four program bindings,
client/authority records, counters and kernel witnesses. Authentication comes
from the fixture authority, not from the extracted header values. Client checks,
authority decisions and program records are SELF witnesses. PREVAIL is INDEPENDENT;
process identity and hook bytes are KERNEL witnesses. No cost result is claimed.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Authoritative parser source and disassembly, argument use, hook index, binary identity and tree state; source inspection only | `correlation-discover-01-20260928.json` | `d2c91c295818b884885b0cf356fea2ebd2da546e285aff99bb56e3531e8f516f` |
| Retained failed build: PREVAIL passes, but the native test exposes five requested maps against a four-map host limit | `correlation-build-01-20260928.json` | `62f11dd0e4a7d9ea39690009076d0ac353dbc99ea5925fd2a3e6913c1afd535b` |
| Corrected four-map reader passes pinned clang-18/PREVAIL, monitor signing and native interpreter/JIT checks; retains three prerequisite program receipts and exact sources | `correlation-build-02-20260928.json` | `17c2ff0187ace9b2449deb94f7812483efaceddaf5ecd559cb6e5a6ef1e6521e` |
| Recreate only the isolated template fixture with the pinned repaired image; preserve toolchain identity/state | `correlation-create-01-20260928.json` | `2d09310ad79d23f0749a5cb2c9c24ba6a91f2e07ec99803c3187a768ee27208c` |
| Retained lint failure: subclass request signature differs from its parent; corrected before the successful live run | `correlation-lint-01-20260928.log` | `18b94e8e01b1e7c5eb89f7c9057469bf9170ea86df2b38d19d110406e089ce42` |
| Retained attempt 01: Black stops the recorder before hook attachment; no fixture result directory is created | `correlation-live-01-20260928.json` | `d75df4315d72a512a305bc36b253d0422ed51b5958065709bc189f7acc6a1dc7` |
| Live attempt 02: 313 calls/records; 51 completed header observations yield 42 accepted-operation matches, one authenticated rejection and eight unknowns. Reordering and five missing/invalid-evidence checks pass. Four restored hook sites, stable process, zero restarts/drops/new errors/selections; Black and scoped pylint pass | `correlation-live-02-20260928.json` | `2476016e4af2afa52a86a5d1e8a166c7541724108193e6e4e8ec025fd79b7f29` |
| Final source/hash/syntax and scoped lifetime lint checks pass; slots 5–8 disabled and configuration status refused; exact final-check sources retained | `correlation-snapshot-01-20260928.json` | `e401a5dce5e1062a431583ce0f097c2e24cc698fa4f6c04f369f88e2673c436a` |
| Archive and remove the fixture after checking four restored sites, matching runtime/process and all 12 inactive slots. No project resources remain; toolchain identity/state preserved | `correlation-cleanup-01-20260928.json` | `4902629d8a0843d1cbb87b6b8193436b140b482197624b035cabd993a34c9b50` |
| Nine fixture evidence files, checked against the source-volume manifest before removal | `correlation-evidence-01-20260928.tar.gz` | `bde46120b8ee02380668a97e61d1e3e68131a340abdedbb7597c889c527f348f` |

### Parser lifetime, 2026-09-28

[Registered experiment](env/ai-traffic/LIFETIME.md). Source inspection is separate
from a live lifetime result.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Authoritative callers of parser initialization/cleanup, client/server/string/trailer parsing and HTTP reset helpers. Includes all matching source files, build-box instructions, packaged hook index/runtime identity and tree state | `parser-lifetime-discover-01-20260928.json` | `b4aadf4a218dc553efc198e147c272b14561b4acd995145630fcee3bd1cdc27b` |
| Three final bound programs pass pinned clang-18/PREVAIL; monitor signatures and three-VM native interpreter/JIT checks. Includes exact program/helper/test sources and the pre-run contract | `parser-lifetime-build-01-20260928.json` | `9855ad6a8fed1489951f8761043a19ea8577830bea4f9c46c47569a5932c68d7` |
| Recreate only the isolated template fixture with the repaired image; preserve the toolchain container | `parser-lifetime-create-01-20260928.json` | `38151d08837ec102d48c9a5bbdae1a79f45f3b45d5eca0e1dbca223dc8a35248` |
| Live gate: 204 calls/records, 71 closed observed parser lifetimes, 66 address-reuse pairs, 48 known and 3 unknown completed header attempts. Three kernel pad witnesses, stable process, 53 HTTP responses, disabled programs, JSON/XML success; attribution gate remains closed | `parser-lifetime-live-01-20260928.json` | `dbad0c97ab48c807faff6b0d61a13211c78a40bbdb820d2f6ed214a36a90483d` |
| Retained final-check attempt: source hashes and shell syntax pass; stops on two intentional broad cleanup-catch lint warnings | `parser-lifetime-snapshot-01-20260928.json` | `257413cd0d3d7bb20d8f89ad7a90762a5f6707d97bac07f486237613e3f5910a` |
| Final source/syntax and scoped lint checks pass; all three slots disabled and configuration status refused. Broad cleanup catches and convention/refactor lint rules are excluded, as recorded | `parser-lifetime-snapshot-02-20260928.json` | `4a578873eda02458cd23076a42b142743b1bca98b7ab0ac7060dbc8ac628c501` |
| Archive and remove the recreated fixture: same runtime identity, three restored pads, 12 inactive slots, no project resources left; toolchain container preserved | `parser-lifetime-cleanup-01-20260928.json` | `2f3f28077219c90b8018d942bbf8c80a1d7cd9016d348914f6bf0a6997cf8a57` |
| Eight fixture evidence files, each checked against the source volume before removal | `parser-lifetime-evidence-01-20260928.tar.gz` | `a6da9e72c8537c6f65e0cf52eb1005ebcfcf527f0281491c16a0fa0bbde43823` |

### Lab fixture cleanup, 2026-09-28

[Cleanup record](env/ai-traffic/CLEANUP-20260928.md). The receipts contain exact
driver sources, command results and before/after state. Failed attempts are
retained. Resource state comes from Docker/Kubernetes. Process memory is a KERNEL
witness; loader status is SELF. This cleanup does not establish traffic health.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Build inventory: three two-container fixture projects, their mounts/volumes, disabled loaded programs, process scan and temporary-file candidates | `vm-cleanup-build-inventory-01-20260928.json` | `dcf4b23b8a2dfe28fdb6887be839e6176f6eec9d21084ee9912867ab67e1416e` |
| Deployment inventory: five jig-owned resources, shared pod/container identities, routes, disabled loaded programs and process scan | `vm-cleanup-deploy-inventory-01-20260928.json` | `44c15a58f3ac9879696a0af169c9b9e3c08c14ed397a3dbe4c51e93af05b44fa` |
| Build attempt 01: absent deployed hook index stops the driver before deletion | `vm-cleanup-build-01-20260928.json` | `875562de2db36f538a4dae5024bf39c4d29e37171b6c2d9de8514689d0be6a69` |
| Deployment attempt 01: same absent-index error; no deletion | `vm-cleanup-deploy-01-20260928.json` | `ddccd0de93340dd34626454df77c52eff658b189422b351d4b78d074e250cdf1` |
| Build attempt 02: two evidence archives checked; older DLP Compose checksum stops cleanup before deletion | `vm-cleanup-build-02-20260928.json` | `8764bcb07b0a7ac7b44d77026acbb115d91d20dd8c0b8a4249317332da988e6f` |
| Build attempt 03: all three archives verified, 177 files retained, six containers/six networks/ten volumes removed. No matching test process remains. Toolchain identity/state unchanged | `vm-cleanup-build-03-20260928.json` | `ad87f052a58f616a6082ddf099e25f6ac0c6836851c6bfce26dde6b0ebac50f5` |
| Deployment attempt 02: five jig-owned resources removed. Other default-namespace pod identities/readiness/restarts and route specifications unchanged. Shared TMM process, binary, parser pad and disabled slot status unchanged; zero restarts. Includes final backend log | `vm-cleanup-deploy-02-20260928.json` | `dca82e1bf56a69612c1496cc408c107efcc8a2fd37388f5bc7bc1b1ae75d3602` |
| Configuration fixture evidence archive; 39 files, verified against the source volume | `eob-config-20260925-evidence-20260928.tar.gz` | `e1349709a29f663bd7cda1f5173937569c8c4dec4fdb0644c670edcbc04ca6cd` |
| Tutorial/parser-scope fixture evidence archive; 113 files, including failed attempts, verified against the source volume | `eob-template-20260925-evidence-20260928.tar.gz` | `2d8cb1fc2ea35c4df54d678f1907bb0b8a4d869c3b6e7af013bad0dd129c371f` |
| DLP/attribution fixture evidence archive; 25 files, verified against the source volume | `eob-dlp-20260924-evidence-20260928.tar.gz` | `a186d37a57ba90153e7722d165aea7555d125b30b4c0b0225c6c47719e904e8c` |
| Exact final cleanup driver. Earlier driver sources and hashes are embedded in each receipt | `vm-cleanup-driver-20260928.py` | `c28dfb9bf4673e410401272ff1c8388cb81328c526c587ea64678212a7c267e6` |

### Attribution parser scope, 2026-09-28

This experiment tests the observation boundary before enabling attribution.
An anonymous address tag records equality within one thread. It does not prove
an object lifetime. The [registered gate](env/ai-traffic/ATTRIBUTION.md#live-parser-scope-gate--registered-2026-09-28-before-the-run)
requires unsampled records and keeps request scope unvalidated.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Authoritative TMM HTTP source, headers, build-box instructions, packaged hook index and runtime identity. The parser preserves partial state and returns `ERR_MORE_DATA`; the client wrapper resumes it. `http_ingress_initialize` increments a connection-local counter and also handles responses. Includes source hashes and tree/container state; source inspection is not a live lifetime result | `attribution-discover-01-20260928.json` | `0364f9e7af41e66d279d19b98e81d3a25080278498234515efef1c2ec799ff09` |
| Pinned clang-18/PREVAIL, exit admission and packaged binding pass for the scope probe. Interpreter and JIT checks pass for partial/completed results, opaque address reuse, table capacity without eviction, null address, output refusals and saturated count. Exact sources, tool/input hashes and monitor signing retained. Build `ca69b84f…`, object `72136c0a…`; bench output uses a test sink | `request-scope-build-01-20260928.json` | `7debab6f6536c20fd59b055bc02375fb0107743f2764c83f0f361e132dad67b3` |
| Live attempt 01 stops at a recorder assertion: it incorrectly requires a lifetime SAFE_RETURN total of zero. The retained slot counter is 16 before and after the first observed call; the new probe selects none. One call produces one record. Cleanup disarms/revokes and kernel bytes are restored; process/container identity is stable, restart count zero. This is a failed test, not a scope result | `request-scope-live-01-20260928.json` | `9c407407acaa00456e5fdfaffdebfad52a685b857b9ece675b9f8ccb0ff3b6c7` |
| Live attempt 02 passes JSON/XML checks: 61 HTTP responses, 54 accepted fixture operations and seven intended rejections. Armed window: 66 calls/records, 59 successful header parses, seven partial returns. Three fragmented requests each produce `17,17,0`; a paced body follows its successful header parse. Eight address tags appear across multiple independently opened client connections. All 59 attempted joins remain unknown. Zero new errors/selections or reported drops; call/NOP cycle, stable process/container and zero restarts | `request-scope-live-02-20260928.json` | `61d6c42b4e60dbb2859530f2cf018cc1df8926d3910ce2087150f02f4229f35f` |
| Failed attempt's exact fixture source, registered gate, build/live receipts, disabled slot state and formatting/lint/shell checks | `request-scope-snapshot-01-20260928.json` | `8179e1df1a37f44a804084b921bf20adc233039b53c9b7683cff83a2ea49d185` |
| Corrected fixture source, both live receipts, original registered gate and build receipt. Final slots 5/6 disabled; configuration status refuses. Black, pylint and shell checks pass. Sources and nested receipts carry hashes | `request-scope-snapshot-02-20260928.json` | `f5667e77d4c9a6a4fd6eba120679f7f610755e7bfc71d7a40f939c82700eaf78` |

### Unsampled observability repairs, 2026-09-25

The repaired host and schema-2 tutorial were checked on the pinned build box.
Build, package and live results are separate records inside the snapshot.
The live run used `tmm:OBSERVABILITY-20260925`, build
`ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`, runtime SHA-256
`05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611`.
Witnesses are SELF for host counters and native assertions, INDEPENDENT for
PREVAIL and the HTTP client, and KERNEL for executable bytes and process state.
These tests establish neither a per-call cost nor loss-free output under pressure.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Live repair test passes: 126 exact HTTP responses; 112 tutorial calls and records; eight precursor calls and 16 records; one-entry HASH works after output-map replacement; revoking slot 6 preserves slot 5's count; 16 monitor selections; zero reported drops/errors; three call/NOP cycles; stable process, restart count zero | `observability-live-01-20260925.json` | `d7fe04a212d52a6f76cf159bd1203f64d246156c50e77f910f9a083614477980` |
| Receipt bundle and exact source texts: host attempts 01–03, tutorial checks 06–07, configuration regression, build/package, signing, isolated deployment, live result and final state. Host checks cover all 256 capacities, collision/deletion handling, two threads across 100 replacements, stale references, busy reset, output delivery/drop/off. Includes retained compiler-bound and retired-generator failures. Final black, pylint and shell checks pass | `observability-snapshot-01-20260925.json` | `f6f1b3a85daadc00c404cd67395b2f77779c8887bb38069ca5262b0a301f1bc2` |

### eBPF tutorial, 2026-09-25

The tutorial checks ran on the pinned x86-64 build box. Receipts contain commands,
tool versions, source hashes, outputs and failures. Bench attempt 05 covers both
execution modes and target binding. Live attempt 03 completes both variants but
fails sampling. An earlier live attempt exposes map-storage reuse after revoke.
Both host defects have build-box reproducers. No cost result is claimed.
These are the earlier attempts. The [repair records](#unsampled-observability-repairs-2026-09-25)
supersede their open status without removing the failed evidence.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Attempt 01: staging omitted `ls_core_relo.h`; retained build failure | `template-check-01-20260925.json` | `724e01209e50ba9bf66c4a6a5ed660c4f83f8285692fcff4ddcf3e31020a011e` |
| Attempt 02: entry passes PREVAIL but native check fails with a one-entry hash map | `template-check-02-20260925.json` | `8c4eda7a9e81751038300684a19dc90c569747b4a31db004887b918fb9a1f2be` |
| Attempt 03: same failure with explicit `flags=8` map-failure output | `template-check-03-20260925.json` | `4e1abb81447b5c13d17bfc4cdc15f67c1b21c6a771866ebe0e0f032d876d30fb` |
| Attempt 04: 256-entry map shape; entry/exit PREVAIL and interpreter/JIT pass; unrelocated entry fails as expected | `template-check-04-20260925.json` | `d9536c1e25841bf08c7565c6e0b60bbf0b481506f44adc074267538165a34059` |
| Attempt 05: final source; bench, input builder, event decoder, malformed-length refusal, packaged entry/exit binding and final PREVAIL pass | `template-check-05-20260925.json` | `b7b736f00ed9c702a327be1beed8261dc1ae50a03ebbe543c00051ed106771ce` |
| Signing: exact attempt-05 objects, monitor ceiling, packaged runtime identity | `template-program-build.json` | `fe5b6953b934203999d2348996a6ce37a3716d4dffed8a519e035829dd108005` |
| Live 01: existing configuration fixture; missing-input output works, then state map fails; hook restored | `template-live-01-20260925.json` | `c441a0e6a9b3a45143ebb4c8cd7a17cf440c88e1c7eb440085b2f3802d7beb51` |
| Fixture 01: retained compile failure; missing uBPF generated-header include directory | `template-fixture-01.json` | `8367625f88176042728dadb5f6c80b110234ed17784efeb13c57c58742345d0e` |
| Fixture 02: map-reuse falsifier returns 1; registered HASH still has ring storage; starts separate SSA fixture using the same image | `template-fixture-02.json` | `9240eebaea14f244ecf24d8a356544a4243016ab9452c5d96196be46f8cbfb29` |
| Live 02: fresh fixture; entry fields, state and threshold work; sampling fails; monitor audit records and restored hook retained | `template-live-02-20260925.json` | `2f711feda2195efe97a7b251f5007d9e919abf87f83bf73fe4dd9ed2f8590fa5` |
| Live 03: both variants complete; 118 exact HTTP responses, 112 calls/events, 16 monitor selections; both sampling checks fail; two restored hook cycles, no restart | `template-live-03.json` | `31b1d36515f4e29ac01001b7a99339f2cde48b9f878d5560a6b51adf167fdeda` |
| Final snapshot: source texts/hashes, real output bridge reports -1 for delivery and 0 for a drop, lint/shell checks, both fixtures disabled/revoked | `template-snapshot-01.json` | `5abd30b89f107e18e06bab68ade987bc085991dc3a91ede54c3a3f444a38020e` |

### ASD-STE100 Issue 9

Downloaded from the publisher on 2026-09-25. The PDF is available locally for
checking writing rules and the approved dictionary. Downloading the file does not
establish that a document complies with the standard.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Full ASD-STE100 Issue 9 standard, from [the publisher](https://www.asd-ste100.org/assets/files/ASD-STE100_ISSUE9.pdf) | `ASD-STE100_ISSUE9.pdf` | `d1f4ea9e7cd6e46b47aa9057209f99e78c0e9cfc4e27a5b07895b05c1a166431` |

### Configuration snapshots, 2026-09-25

P21 runs on the pinned x86-64 build box, with separate staging and an isolated SSA/Tao
deployment. Bench, build/package and live lifecycle evidence are distinguished below;
none is a data-path cost measurement.
Commands, tool/source hashes, stdout, stderr and failures are retained in each receipt.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| First PREVAIL attempt rejects the sample: `Invalid type (r1.type == map_fd)` with static map symbols / pinned clang-18 and PREVAIL | `config-snapshots-check-01-20260925.json` | `5a84c47b1f0cfe3d7f4f815db9e02d69209b9ade8c009130ae6e64644ceeb82e` |
| Global ELF map symbols fix admission; interpreter/JIT, 10,000 publications/four readers, stale identity/revision and mutation refusals, actual socket-handler framing, CLI error handling and changed-TU syntax checks pass / pinned build-box harness | `config-snapshots-check-02-20260925.json` | `db77a519dedefaabbf8893afabb367dd1f6761eb3ed67665bfdd6cf06ee2fb21` |
| Latest source rerun adds sticky-unavailability, empty-snapshot withdrawal and existing cross-TU map/helper regressions; all pass. Concurrent run observes 3,643 coherent reads and 175,742 unavailable attempts, with no mixed successful read; this is not a performance/availability budget / same harness | `config-snapshots-check-03-20260925.json` | `36570345e340c155f44fc185545bab6910141617bdcb456715dbd99dfe061e22` |
| Read-only integration preflight: existing build-tree/staged source hashes agree; candidate differs in intended P21 files; toolchain and isolated fixture running, no make/compiler process in captured inventory / build box | `config-integration-preflight-20260925.json` | `f4a251889b42e87f71542b098609c5113497b4226dd89c9d8a42062a5310ccbd` |
| Working-tree staging matches by content; subsequent direct invocation of non-executable sync script fails with Permission denied / retained attempt | `config-source-sync-20260925.log` | `b931c5d0e49066adedf6deb214b1998c1490b8805a9826a376a3a8efe2a7694a` |
| Sync invoked with sh succeeds; prior differences inspected, configuration header/source copied, generated public key excluded, substrate object invalidation confirms zero remain / build box | `config-source-sync-02-20260925.log` | `8212670119e31265cede59e305c5fcb708e704329b2db5386c2f59c7eb034744` |
| Existing wire-layout/header, audit and loader-client regressions pass / pinned build box | `config-legacy-checks-20260925.log` | `3f5b146c403b0ab3f3711ad16e648cca476d5bfdd733e07b557f13065f3bb1aa` |
| `make tmm` succeeds through the prescribed toolchain; linked no_pgo artifact is fresh, includes configuration globals/code, build ID `a361c87ff9852ad80b46b661a6401f7fecad2b01`, SHA-256 `a1236133…cf3b3`; source and whitelist hashes recorded, signing public key unchanged. Linked build only, not packaged/live / build box | `config-tmm-build-20260925.json` | `be9a348c046ec21582f3c4dae7c584e6cf404321b2a5965db003f29a94214400` |
| Packaging and bake succeed; separate `tmm:CONFIG-20260925` image `sha256:9ea1df6a…b837`, packaged runtime build `b8dc27f34a93db91f91b60f0844105bfb30c6f90`, SHA-256 `26e8f07b12a279e7d84f2328363db998a7dfa109a9b3c71847be408a6710a12c` / pinned build box | `config-package-20260925.json` | `ca82a542e1ad65cbd5f5681e0fba4d29d123349c4884b8d571fac77f6b82e8d1` |
| Packaged-pair discovery, image runtime identity/key match and catalog-free audit pass: 16 layers, 7,504 regular files, 1,318 ELF files / image build gate | `config-bake-20260925.log` | `fa32beb4bc8b1a4ad294cca61461bf62e1cbd1b6e09efd71e1fb14130049743d` |
| Live configuration-only observer compiled with clang-18.1.3, bound to packaged `http_parse_client_headers` at `0xccc600` (+4 pad), PREVAIL PASS and signed monitor-only; final object SHA-256 `82fb7618…73381` / pinned build box | `config-program-build-20260925.json` | `f8522e8af1b9d51aada934f787c45bd2675f5b17ec737fd7af0e53093b264911` |
| First live lifecycle's fixture JSON/XML pass, but outer recorder fails: it incorrectly expected jump opcode `e9`, while kernel memory shows the correct `e8` call and restored NOPs. Retained failure; fixture files recovered in snapshot below / isolated SSA | `config-live-01-20260925.json` | `e43bacf98374ba08f9b8ebe14592420984eb28e790151b9183380bd3d42b8fc0` |
| Corrected full lifecycle passes: 52 exact HTTP responses, 48 armed calls and 48 events across six phases, zero reported drops/errors/safe returns; signed load, missing input, revisions 1/2, empty revision 3, five stale publication refusals, same-bytecode reload/new instance and revoke. Executing `/proc/7/exe` matches packaged SHA; kernel reads capture two call/NOP cycles, same process starttime and unchanged container state/restart count 0 / isolated SSA | `config-live-02-20260925.json` | `efc2652569fa9ade5121a0b6d520aa13b9f4eefecf5f68d187d2812028113861` |
| Both lifecycle attempts' JSON/XML/logs and exact publisher documents, fixture source text/hashes, image/process state, final revoked slot, TMM/audit logs and successful black/pylint/shell checks / read-only isolated fixture collection | `config-live-snapshot-20260925.json` | `3af4d607ad1f576f5c28d9c6b1b15dae3f8fbfddda16d0713179b147d8f56e8a` |

### Agent attribution fixture, 2026-09-25

Destination-authenticated test protocol through the isolated SSA/Tao TMM. Witness is the
authored client/authentication ledger (independent of eBPF, not an independent security audit).
Contract, trust boundary and limits: [`env/ai-traffic/ATTRIBUTION.md`](env/ai-traffic/ATTRIBUTION.md).

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Two-agent run: 23 attempts, 17 accepted, six rejected; 15 attempts share one backend connection, eight interleave on two additional connections. Spoofed claim remains A; forged credential remains unknown; replay and invalid delegation rejected; valid B execution retains A's parent/origin. Includes exact source hashes, client/server ledgers, configuration ACKs, container identity, formatting/lint checks and regression of result-checking against retained failed/successful ICAP receipts. **Recorder limitation:** executing-ELF inventory is empty because its name filter omitted `tmm64.no_pgo`; corrected in the follow-up below / build-box isolated fixture | `ai-attribution-01-20260925.json` | `1b111d69ddfb800a7cee8a28b31cd47ca970909fd0b7ea45166dbd1945f7264d` |
| ICAP monitor authoring preserved: build receipt plus object/signature hashes; compile, five relocations, target binding, PREVAIL and signing, without a live attach result / `result.icap_probe` in the same snapshot | `ai-attribution-01-20260925.json` | `1b111d69ddfb800a7cee8a28b31cd47ca970909fd0b7ea45166dbd1945f7264d` |
| First runtime-recorder correction fails explicitly: executable name now matches, but runtime image lacks `readelf`; swallowed OSError still leaves inventory empty. Test receipts unchanged / preserved failed collection | `ai-attribution-runtime-20260925.json` | `b0833cd1301c54015bab408a937a2c708342455438877607b2f0825c6c70a5a1` |
| Corrected collection: `/proc/6/exe` resolves to `/usr/bin/tmm64.no_pgo`, SHA-256 `a4b9e777…afd7`; identical to packaged build-box runtime whose ELF notes identify `c3b81927dfdcc31137cd8212b5e23bb85677a06c`. Includes process stat, container identity, original unchanged test receipts and all successful collection/check statuses / build-box + isolated TMM | `ai-attribution-runtime-02-20260925.json` | `d9643e82345dd346a44e560c8d55a7724235ba089eedf46501ce46ef47d61673` |
| Conservative join consumer passes 19 checks in the pinned SSA/Tao fixture. Retained 23-attempt authority ledger plus **synthetic** candidate observations yields 16 attributed, four rejected, three unknown (two ambiguous replay candidates and one unauthenticated attempt). Fresh fixture proofs verify A/B with one nonce, then reject replay; all three candidate joins remain unknown. Missing scope/accounting/rows/events, drops/errors, duplicate request identities/candidates and incomplete authority data fail closed. Includes exact source text/hashes, container identity, black/pylint checks. **No live TMM attribution join or request-lifetime qualification** / isolated fixture consumer test | `ai-attribution-join-01-20260925.json` | `9cb7d8e735b90b3b0dd697bd0f9b5d190df14fe05718061a2a72238364dc6dad` |
| Follow-up adds explicit ledger-order and event-order permutation challenges: all **21 checks** pass with the same dispositions. Both test receipts and current source/check provenance retained; synthetic observations still do not qualify a live producer / same pinned fixture | `ai-attribution-join-02-20260925.json` | `fb27a8605c8b35ca25512cabe4738732b858fad37fa1733969a1b8e8f1c45581` |

### Isolated inspection fixture, 2026-09-25

Build-box SSA/Tao harness receipts. Forwarding is measured; inspection outcomes and hook cost
remain separate experiments. Exact scripts and their hashes are embedded in each receipt.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Initial test-image bootstrap failed on authenticated schema download, HTTP 401 / isolated build-box fixture | `ai-icap-bootstrap-401-20260925.json` | `f9ca25f5bcb08c494beb1eb6b91f45e52574fd0eab6bb30e35495402abf90fda` |
| Bootstrap recovered with hash-pinned schema cached by the authoritative toolchain; healthy fixture, no TMM yet / same fixture | `ai-icap-bootstrap-recovery-20260925.json` | `ceb093226772956734c17c7b22e8cf9197020bff52e8ae5636517898c386f6ee` |
| First SSA baseline failed before forwarding: synchronous DPC-return validation enabled on asynchronous NATS transport / fixture test log and TMM startup | `ai-icap-baseline-attempt-01-20260925.json` | `978ad094bbf1dd674b4900e3d41ad7613140ea49c6e2e00e555b1ec0b14e5e4e` |
| Second SSA baseline: successful asynchronous acknowledgement and exact HTTP response through isolated TMM; origin sees TMM self-IP. Includes transport sources, runtime identity and retained first failure / fixture + TMM | `ai-icap-forwarding-baseline-20260925.json` | `b36acc177295bedab789fc3346fee5830db39defc1dc32db679696584997ae1a` |
| First gate attempt fails: reused IDs across different configuration objects, IVS not found, reset before inspection / fixture and TMM logs | `ai-icap-gate-01-20260925.json` | `3c9d9d031c454b7c12c216f95fb7a659e5f7b6d23f0fda89c51115e180a7f1ec` |
| Second gate attempt reaches complete inspection but fixture wrongly requires Allow: 204 on a preview request; no verdict emitted / same fixture | `ai-icap-gate-02-20260925.json` | `b87db65f0e388fc061efe0b1b00ded818ba0ca72942ceea7d7bbd32e6ed9af2c` |
| Third gate attempt: delayed allow, deny and fail-closed timeout pass independent client content/application-read checks; one request each, identical 33-byte body / same fixture, no eBPF attached | `ai-icap-gate-03-20260925.json` | `627464989b9f5fa7e9e6020fe87256c78b8cc26421584cd6e7180bed03607c95` |

### AI inspection integration preflight, 2026-09-24

Read-only investigation on the authoritative build box and stable `kind-vs` pod. These receipts
establish source/configuration facts, not a live DLP result. Scope and open gates are in
[`env/ai-traffic/INSPECTION.md`](env/ai-traffic/INSPECTION.md).

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Adaptation sources/iRules interface, ICAP configuration test examples, build-keyed hook/signature candidates, installed CRD inventory/selected schemas, executing ELF identity and ring configuration / build box + datkube | `ai-inspection-preflight-20260924.json` | `2f06ed79f38f5f64b78ab95aacd3899f1bd545f6961a4777c098622b4a7701f1` |
| Follow-up adds inference response-passthrough and lossy ext-proc mirror source, plus the ICAP test's separate configuration-server transport; repeats runtime/schema checks / same authoritative hosts | `ai-inspection-preflight-followup-20260924.json` | `e15c9b669c78579525e3e53a9be5358f1a5aaa4d89377e00b5222443c8f08bb8` |

### F5 AI Security Platform overview, 2026-09-24

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| F5's stated platform scope: application/workforce AI security, runtime protection, continuous red teaming, agent/tool governance and data loss prevention / [official overview](https://www.f5.com/products/ai-security-platform#overview), selected text excerpts retrieved with webfetch; product positioning, not independent efficacy or implementation evidence | `f5-ai-security-platform-20260924.md` | `b475f6d710a1f3d6ae9e74189842655dbd86de85a29924e991fcce45b183216a` |

### AI traffic fixture (P19), 2026-09-24

Own-system tiers and scope are recorded in `GROUND_TRUTH.md` and `env/ai-traffic/README.md`.
The client/backend ledger is authored fixture instrumentation, independent of the eBPF substrate;
the loopback check is separate from the live proxy run.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Loopback jig check, 51 exchanges/6 streams, source hashes / build-box console receipt | `ai-traffic-loopback-20260924.log` | `e4bc27f84beff232403c5d4b861e7b963add2b6a2d8c64ed802a28e7a3f66438` |
| Runtime/pod identity, source hashes, installed fixture resources and scoped neighbor pins / datkube | `ai-traffic-preflight-20260924.json` | `83eebee77d2748362dcf0724a31852f80b1aee242bfe9841c2c1440cd5b39c49` |
| Live client timing/body hashes plus origin events and exact reconciliation / fixture client through TMM | `ai-traffic-flows-20260924.jsonl` | `e080caaa5052e6e6d11f9e15799ca093d22eb802ea6c27bf46854eab975da119` |
| Separate origin stdout copy / kubectl logs | `ai-traffic-origin-20260924.jsonl` | `d89ceda0db504ec8b2e3f1a9663f48f4f17f1962e94fc154e53d959938419a75` |
| HTTP proxy configuration with native AI filters disabled / Kubernetes virtual-server object | `ai-traffic-listener-20260924.json` | `cb2a0a5acd81eaad60e859a9a2e986d6fd0735b18d09b42e191343731f9788c9` |
| Selected TMM client/VIP traffic and listener name / TMM tcpdump, 20 packets | `ai-traffic-packets-20260924.log` | `058f0a009e33659fd331b5f33c9ca119f7eb704a7dce82b70eff2020d499e688` |
| Passed run summary and final stable TMM identity / datkube driver | `ai-traffic-result-20260924.json` | `96e22dfd1877e137f47f3b744e5d47c80d6d6766cb6ff5eebbc9078ed4f314f7` |

### Application-metadata hook discovery, 2026-09-28

Authoritative build-box source and packaged-binary inspection. No compilation,
attachment or live native-filter test. [Probe contract](env/ai-traffic/METADATA.md).
Both receipts retain exact source, hook index, binary identity, commands and driver.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Initial source shortlist on packaged build `ca69b84f…`: no hook-index entries for `a2a_request`, `a2a_lookup_method` or `aimcp_request`; padded response/persistence/inference/server-header entries, with selected disassembly. Full A2A/AIMCP source and JSON interface describe on-demand parsing and length-delimited escaped strings / build box, source and binary inspection only | `metadata-discover-01-20260928.json` | `c87063a42829c15f04e70e915552043020e5c6c13250695bac29b2542dbbfdb9` |
| Expanded shortlist includes padded `hud_a2a_handler`, `hud_aimcp_handler`, `a2a_walk_and_replace`, `tmm_json_object_get` and `tmm_json_value_get_string`. Source distinguishes unknown methods, normal responses/SSE messages and stored MCP session/pool/endpoint state. Binary SHA `05d17517…a9611`; hook-index build ID matches ELF notes. Argument/field lifetime qualification and live extraction remain pending / same package and source tree | `metadata-discover-02-20260928.json` | `bc408a848aa450078262fed1a5444a2d5159324643c4b2c39d15bcf6102fcc0b` |

### Native-handler event probes, 2026-09-28

These receipts establish event-code extraction, not method/session field extraction.
Build tests use the pinned toolchain. Live records and clients are SELF evidence;
hook bytes and process identity are KERNEL evidence. The live receipt retains the
formatted decoder used there; build 01 retains its earlier, equivalent source.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Handler argument layout, pinned event enum and native-filter fixture source / build box | `metadata-discover-03-20260928.json` | `e2e0de92a19b67f69e2c724d45f78252a8fd740c8dc71e9c31d89e431ff9749f` |
| Both probes pass pinned PREVAIL and real interpreter/JIT checks; numeric event codes, presence bits, output refusal and instance reset / build box | `metadata-build-01-20260928.json` | `77d6249f0e4e69d4086dc1009973bd6b5b157a412f81e7f2ceb9aa56c47495d7` |
| Isolated fixture creation / build box | `metadata-create-01-20260928.json` | `48a9180bbd62add2a0d02512fd8ad95a7ee157b60f24ec299d843300b009b522` |
| Retained standalone inspection failure: `AttributeError: module 'tao' has no attribute 'runner'` / build box | `metadata-preflight-01-20260928.json` | `d56a0561de19640ada5c4a3f1695164eb703036ae08f31ebb90529b168f9d2a7` |
| Configuration interface inspection succeeds after removing unnecessary Tao imports / build box | `metadata-preflight-02-20260928.json` | `a6e4e60b830d4506e63313056e94188beac52083829fd83da1d18fa92395741e` |
| Eight requests through native filters; 192 records / 192 calls, 96 per handler, 22 event codes per handler; no reported loss, new VM errors or process restart; restored pads / isolated fixture | `metadata-live-01-20260928.json` | `97cf52b09632725fbacb4d8fb1a90a2094f76f2025be8919234a165e682e0b1b` |
| Slot/pad checks, evidence archive and isolated fixture removal / build box | `metadata-cleanup-01-20260928.json` | `ccc10f112fdc742f0e9773b82782ef1cdeba8120ce834c1788f780cffe9f2837` |
| Archived live fixture result, logs and source files / build box | `metadata-evidence-01-20260928.tar.gz` | `526a42461530f8db00cdb1a2239fbf83796aceb28da803c9706b2bc2c23202cb` |

### Root-object method extraction, 2026-09-28

The field probe reads an application's returned string after checking its owner
and member key. It does not infer a request identity or decode untouched fields.
Live value comparisons are SELF evidence. Hook restoration and stable process
identity are KERNEL evidence. PREVAIL is INDEPENDENT admission evidence.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| JSON parser source and packaged debug layouts: value owner, member key/value links, circular list and string descriptor. No indexed `a2a_get_subtree` hook / build box | `metadata-discover-04-20260928.json` | `add07c4e5d2372d63331e475584f9a3aa950d3dcd202343f89d0bd79719fcc47` |
| Retained PREVAIL failure: first record layout exceeded the 256-byte stack limit; not loaded / pinned build box | `method-build-01-20260928.json` | `aeee0a5e32a463d4048b15ae91080db74cc56c2d60e41dd205c47aa019c7a5fb` |
| Revised 144-byte record passes the same PREVAIL limit and exit admission; 40 interpreter/JIT records check exact values, escapes, lengths, guard pages, scope, budget and output refusal / pinned build box | `method-build-02-20260928.json` | `4bafaa39b6b985d1464820d6d8d5a195454509405a477deeb8528fd33ff1c0c1` |
| Isolated field-test fixture creation / build box | `method-create-01-20260928.json` | `23b2268527a1ffe322ebc48f20650822c0a1c9d7e7e5067e6b15ad43363c138c` |
| Ten live requests; six exact string/prefix comparisons, one getter error, one exhausted walk; nested-only and AIMCP inputs produce no getter calls. Eight calls/eight records, no reported loss/new VM errors/restart, restored hook / isolated native-filter fixture | `method-live-01-20260928.json` | `99a55f596c65f6450ba58881db0fea67accc9de5ddf35605746445b9253d8c9f` |
| Verified disabled slots, restored pad, archived evidence and removed only the isolated fixture / build box | `method-cleanup-01-20260928.json` | `d42660a3fd2f1d2caafcd643fafd1f6ca6c92d53bef4aa335ad7312f190cb4a6` |
| Live result, Tao logs and configuration receipt archive / build box | `method-evidence-01-20260928.tar.gz` | `faab547e916cee6df0008beaaa4138d7518b836bf7f3c155c5a8fed8473bad1b` |

### AI protocol source inventory, 2026-09-24

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| A2A protocol processing and AIMCP session-persistence sources, active filelist entries, source hashes and selected excerpts / authoritative build-box TMM tree at `e2104734a940a099a9190eb84bfbea01fb4b81d4`; source inspection only | `ai-protocol-source-20260924.txt` | `f9014e986fbfb53af272393262fb9ac1c3ce3d84bfbc85e305c49f26b15d7202` |

### Embedded-structure traversal (P17), 2026-09-24

The fixture, real-target authoring and live results have separate scopes in
[`embedded-traversal-validation.md`](embedded-traversal-validation.md) and `GROUND_TRUTH.md`.
Failed pre-probe network attempts are retained alongside the successful run.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Native offset/value oracle, pinned PREVAIL, interpreter/JIT and refusal checks / build box | `embedded-fixtures-20260924.log` | `7a5e2d02362c3af81c59ac01bcfd37dbf918797de29fd815978abbb81fe161aa` |
| Preserved legacy catalog, 12 real-TMM relocations, final target binding/verification/signing / build box | `embedded-authoring-20260924.log` | `18ce81443d72372afa8f9faf4b729c7d9715122c29dffd95eb86bbed7700b545` |
| Exact real-target authoring driver / build box | `embedded-authoring-driver-20260924.py` | `82815c5ea3637a3f87b8c9a2ff0edc504fcc4895a41c4bb44cdcc2439fe4557f` |
| Three live HTTP/1 probes, counters, independent patch readback, stable pod/cleanup and competing ARP replies / datkube | `embedded-live-20260924.log` | `6b0b719c97ce1bf74729538e3d38c106c17d3cb1cbed9b9e34d75231d03aadf8` |
| Exact pinned-pod live driver, including unexercised neighbor-pin fallback / datkube | `embedded-live-driver-20260924.py` | `16e807d2c814ba68717f7ddc61a56eb7d49c47a3ac7fb4e99d8f90e3eeeac31e` |
| Failed baseline warm-ups before program loading / datkube | `embedded-live-warmup-failed-20260924.log` | `6e6a5bb3ead81a9646c3a776173351669041148edf48135cfb09277100ba03e7` |
| Failed baseline, captured backend handshake and competing-MAC reset / datkube | `embedded-live-network-failed-20260924.log` | `96891fc7568a54a362a82a3874fd53ce0ed93e16bec71566656a35895f355ae5` |

### Catalog-free deployment, 2026-09-24 — build-box / cluster receipts

Own-system results are tiered in `GROUND_TRUTH.md`; these files also anchor claims about the
external TMM build and toolchain. Full hashes are repeated in `evidence/cache/MANIFEST.sha256`.

| Claim / origin | Cached file (`evidence/cache/`) | SHA-256 |
|---|---|---|
| Previous CTX96 image still carried TSV catalogs / build-box Docker | `catalog-before-20260924.log` | `6adc37ec222a8de310351457a01c23e44e25e7d42c7b087e8a8ec2537e072b25` |
| Pinned parser/sanitizer/verifier, signature and client checks / build box | `catalog-checks-20260924.log` | `2d533e62b2119e4675011f43952fb7de250997528f22c258b7f4ba5ade87e3a1` |
| Packaged build identity / build box | `catalog-package-20260924.log` | `5e6c51c79a1c56c763e3ab6ff9e24dd7348cbf73a624aa3a86e267eed2b77902` |
| Build/program/image/layer audit / build box | `catalog-bake-20260924.log` | `2eed800d90c768934fa9da0865f782de49be39cb772a3e4764d652ee28fe0008` |
| Pre-ship content and every-layer checks / build box | `catalog-ship-20260924.log` | `b3a04605d6fff7b9e0ed57d4dcee2a6d73e632909480e5a8df6bb57c1c17406d` |
| Per-node import and rollout / datkube | `catalog-deploy-20260924.log` | `2c986105d8760cf0113937b358780f14bcd83e801a011060020093f41788fb97` |
| Discovery and final DSL verification/signing / build box | `catalog-discovery-20260924.log` | `a4ca48250f576bb7c2c5db333720bd7cd611edc9a916275d4fedd496b36f645c` |
| Final signed probes, including valid different-target control / build box | `catalog-probes-final-20260924.log` | `3a31e5b3c2d8a32a0b39025cc2a43458127f9caee74bb5315ec7032d8de60da5` |
| First live target/context run / datkube | `catalog-live-20260924.log` | `66ebd72e290bed5ebd97fb411ea3770ffe7f4a3f1e10bcfc8bf5766638055f35` |
| Complete repeat with valid different-hook replacement / datkube | `catalog-live-retarget-20260924.log` | `d7cac00e337d97857c2e5f053b94c9e65ea4d6525258c68931bb4cc146dd1a59` |
| DSL entry/exit traffic counters / datkube | `catalog-dsl-live-20260924.log` | `433d381fb694d90b2d4de7725eccb3f661acfa57ea44fbdd6715538d71123370` |
| Initial final pad/slot/identity and fixture cleanup / datkube | `catalog-final-20260924.log` | `76153c90ccd45dde0e22e2d5e9afcd7e99af775d1b2bb6585c32e16d497b0f91` |
| Final repeated-run pad/slot and cleanup / datkube | `catalog-final-retarget-20260924.log` | `c2b34c26ba9ad71a617fe9da87d2e4fe113618678baee872eb4f207cf9e015f8` |
| Full `src/` status, source hashes, file/line counts / authoritative TMM tree | `catalog-tree-20260924.log` | `cf35c19d54fd353c385ef7208ec76c11ab00b08a33e88bba73ce8c68a2bdb1d9` |

### Vendored and retrieved references

| claim it supports | origin | cached file | SHA-256 | retrieved (UTC) |
|---|---|---|---|---|
| uBPF: PREVAIL assumes r1 points to a valid memory region; uBPF enforces no context layout | vendored ubpf/docs/VerifiedPrograms.md @ c900ed9f | [`ubpf-c900ed9f-VerifiedPrograms.md`](evidence/cache/ubpf-c900ed9f-VerifiedPrograms.md) | `4efc1fd5f1dec514cc305b280c47fd76…` | 2026-08-20T12:37:56Z |
| PREVAIL flag defaults: --termination is "Default: ignore", --allow-division-by-zero is "Default: allow", --strict is off | prevail --help, binary in ebpf-verifier/bin | [`prevail-0.2.5-help.txt`](evidence/cache/prevail-0.2.5-help.txt) | `fe2aa37bc987ed99769ad7a294459a04…` | 2026-08-20T12:37:56Z |
| The PREVAIL binary in use is v0.2.5 | prevail --version | [`prevail-0.2.5-version.txt`](evidence/cache/prevail-0.2.5-version.txt) | `35461307fe187b0161fb7e73804548d3…` | 2026-08-20T12:37:56Z |
| uBPF is iovisor/ubpf @ c900ed9faf1d41358a7ea9217ccd0b64a4ee8d5d, 2026-06-12 | git log in the vendored checkout | [`ubpf-c900ed9f-commit.txt`](evidence/cache/ubpf-c900ed9f-commit.txt) | `01d134ae8be5c1ee8f4f3ee8573cc012…` | 2026-08-20T12:37:56Z |
| PREVAIL is vbpf/ebpf-verifier @ 06769f7b508214e63b97905d275920f7e90182fa, tag v0.2.5 | git log in the vendored checkout | [`prevail-06769f7b-commit.txt`](evidence/cache/prevail-06769f7b-commit.txt) | `bb43c4844dca2bb89331dcf7d6c7e1a3…` | 2026-08-20T12:37:56Z |
| Kernel BTF is produced from DWARF by pahole ("The pahole acts as a dwarf2btf converter") and embedded as ELF sections `.BTF` (type+string data) and `.BTF.ext` (func_info, line_info, CO-RE relocations) | docs.kernel.org/bpf/btf.html | [`kernel-btf.html`](evidence/cache/kernel-btf.html) | `325dfc8ea4e2c615…` | 2026-08-26T14:57:17Z |
| CO-RE relo record is `struct bpf_core_relo {insn_off; type_id; access_str_off; kind}` carried in `.BTF.ext` (not ELF relocs); FIELD_BYTE_OFFSET patches an immediate (ALU/LD) or an instruction offset field (LDX/STX/ST); the access string is colon-separated indices | docs.kernel.org/bpf/llvm_reloc.html | [`kernel-llvm_reloc.html`](evidence/cache/kernel-llvm_reloc.html) | `be288617b83ecdec…` | 2026-08-26T14:57:17Z |
| libbpf CO-RE matches a program's recorded BTF/relocation info to the running kernel's BTF and "updates necessary offsets"; kernel BTF is exposed via sysfs at `/sys/kernel/btf/vmlinux`; `vmlinux.h` = `bpftool btf dump file /sys/kernel/btf/vmlinux format c` | docs.kernel.org/bpf/libbpf/libbpf_overview.html | [`kernel-libbpf_overview.html`](evidence/cache/kernel-libbpf_overview.html) | `269e4b0760ff37cd…` | 2026-08-26T14:57:17Z |

**These five are local-origin, and that is the point of listing them.** They are claims about
*external* software, so the rule applies — but the evidence is the vendored source and the built
binary we actually use, not a web page describing a version we might not have. That is stronger
evidence, not weaker.

## NOT_RETRIEVED

The *workstation* has no outbound network (`https://github.com` -> `HTTP 000`, `https://nvd.nist.gov`
-> `HTTP 403`, verified). The **build box (eob-bnk-build-01) does have egress** --- it is how the
kernel-doc rows above and the bpftime arXiv row below were retrieved and cached. So a remote source
is retrievable *via the build box*; the rows below remain NOT_RETRIEVED because they are internal/
paywalled/suspect, not merely remote.

| source | needed for | status | reason |
|---|---|---|---|
| `CVE-2026-22548` advisory | the worked shield example in the walkthrough | **NOT_RETRIEVED** | no network. **And separately suspect**: `DOC-STATUS.md` already records that this identifier does not correspond to a real published advisory. It must not be presented as one |
| `CVE-2022-4304`, `CVE-2022-0492` | cited in the CVE survey as examples | **NOT_RETRIEVED** | no network. Referenced as identifiers only; no technical claim in this repo rests on their contents |
| F5 commit `c806f1b2e8` | `alpn_guard` reinstates this bounds check | **NOT_RETRIEVED** | internal F5 source control, not reachable from here. The *shield* is in-tree and verifiable; the claim that it matches that commit is not independently checkable in this environment |
| Intel CET / `endbr64` semantics | the four bytes preceding the pad | **NOT_RETRIEVED** | no network. Mitigated: the bytes `f3 0f 1e fa` are read from the live process and cached implicitly in every demo transcript, so the *observation* stands even where the specification reference does not |
| USENIX Security '22 paper (he-yi) | prior art in the substrate design doc | **NOT_RETRIEVED** | no network. Cited as prior art, not as support for any measurement |
| Linux `perf_event_paranoid` documented range | the claim that 4 exceeds what the kernel tree defines | **NOT_RETRIEVED** | no network. **Weakened accordingly**: what is measured is the observed behaviour at the setting present (`EACCES` unprivileged, permitted with `CAP_SYS_ADMIN`), which needs no documentation to be true |

## What this list is missing

Nothing external is currently cited without a row here, but this page was created after most of
the repository was written, so absence of a row is not yet proof that no uncited external claim
survives somewhere. Sweeping for that is unfinished work and is recorded as such rather than
declared complete.
| bpftime latency (arXiv 2311.07923) | https://arxiv.org/abs/2311.07923 | 2026-08-25T16:49:24Z | `evidence/cache/bpftime-arxiv-2311.07923-latency.md` | ae368a303e7455b332e51ca834245edad7c6cdd5f9c41b7843711be3fc408405 | CITED-FROM-ABSTRACT — full PDF not byte-cached |

## F5 CVE advisories (reachability-survey CVE candidates, 2026-08-27) — NOT_RETRIEVED

The my.f5.com advisory pages render via JavaScript and return only a loading shell to automated
fetch; NVD returned its home shell. Marked NOT_RETRIEVED — descriptions in `reachability-survey.md`
are from search-result snippets, not cached full text. Retrieve via authenticated my.f5.com when
matching a specific candidate.

| CVE | advisory URL | status |
|---|---|---|
| CVE-2017-6151 | https://my.f5.com/manage/s/article/K07369970 | NOT_RETRIEVED (JS-gated) |
| CVE-2023-44487 | https://my.f5.com/manage/s/article/K000137106 | NOT_RETRIEVED (JS-gated) |
| CVE-2023-22323 | https://my.f5.com/manage/s/article/K56412001 | NOT_RETRIEVED (JS-gated) |
| CVE-2025-61951 | https://my.f5.com/manage/s/article/K000151309 | NOT_RETRIEVED (JS-gated) |

## F5 Bugzilla — reachable-parser CVE landscape (RETRIEVED via REST API, 2026-08-27)

Retrieved from `https://bugzilla.olympus.f5net.com/rest/bug/<id>` (authenticated, F5-internal — not
publicly retrievable, but reproducible by anyone with F5 Bugzilla access + the BZ id). Fields used:
`cf_cve_number`, `cf_cwe`, `cf_cvss_score`, `cf_conditions`, `cf_affectedversions`, `cf_fixeddate`,
`component`, `status`. Search: `cf_type=Vulnerability` + `cf_affectedversions substring Neptune`.

| BZ | CVE | component | fixed |
|---|---|---|---|
| 1496457 | CVE-2025-41414 | LTM_HTTP2 | 2024-04-24 |
| 1357309 | CVE-2025-36557 | LTM_HTTP/fsm | 2023-10-06 |
| 1783773 | CVE-2025-60016 | TLS/SSL | 2025-03-04 |
| 1552933 | CVE-2024-28889 | LTM_SSL | 2024-03-19 |
| 1361169 | CVE-2023-40534 | LTM_HTTP2 | 2023-10-09 |

Superseded the earlier NOT_RETRIEVED my.f5.com rows for these CVEs: Bugzilla carries the full detail
(CWE, conditions, CVSS, affected versions incl. Neptune) the JS-gated K-articles hid.

## SPK Architecture (internal Confluence) — **NOT_RETRIEVED**, 2026-09-02

`https://docs.f5net.com/spaces/~afreeman/pages/560987062/SPK+Architecture` — F5-internal
Confluence, authentication-gated; the sandbox running these tools has no route to `docs.f5net.com`
and the fetch returned empty content. **Deliberately not paraphrased from memory** (rule 1).

What was needed from it — how SPK/BNK exposes a TLS listener and attaches a client-SSL profile — was
instead answered **from the cluster itself**, which is stronger evidence for this deployment than a
general architecture page: `kubectl api-resources` shows the installed SPK family is
**networking-only** — `F5SPKEgress`, `F5SPKEgressSIP`, `F5SPKSnatpool`, `F5SPKStaticRoute`,
`F5SPKVlan` — with **no SPK ingress CRD** (`F5SPKIngressTCP`/`HTTP2`/… absent). So on this build the
networking half is SPK and the **ingress half is Gateway API**, which is why
`env/bnk-dev-runbook.md` §12g says "BNK uses Gateway API". Anyone with Confluence access should still
read the page and correct this row if it contradicts the cluster.

## BIG-IP Next for Kubernetes — CRD reference (RETRIEVED, public, 2026-09-02)

`https://clouddocs.f5.com/bigip-next-for-kubernetes/latest/custom-resource-definitions/` and the
`bnk-bnkgateway.html` / `bnk-gateway-api-gateway.html` pages under it. Public and re-retrievable;
fetched via tooling, **no `evidence/cache/` file stored** — so treat the quotes below as the claim and
re-fetch to audit them.

**The documented BNK CRD set:** `BNKGateway`, `BNKNetPolicy`, `BNKSecPolicy`, `CNEInstance`,
`F5BigCneAddresslist`, `F5BigCnePortlist`, `F5BigDdosGlobal`, `F5BigFwPolicy`, `F5BigFwRulelist`,
`F5BigLogHslpub`, `F5BigLogProfile`, `F5SPKEgress`, `F5SPKSnatpool`, `F5SPKStaticRoute`, `F5SPKVLAN`,
`Gateway`, `GatewayClass`, `GRPCRoute`, `HTTPRoute`, `L4Route`, `F5BigCneIrule`, `F5BigGlobalOptions`.

Three findings that closed open questions in the CVE-mitigation milestone plan (retired
2026-09-05 once the milestone was reached; the evidence now lives in
`cve-41414-demonstration.md` and the procedure in `cve-to-shield-process.md`):

1. **Gateway TLS is certificate-only.** Under `listeners.tls` the reference documents
   `certificateRefs` (with `group`/`kind`/`name`/`namespace`) and *nothing else* — **no `options`
   field is documented**, and there is no cipher, cipher-group, `dhGroups` or ECDH-curve setting.
   Independently confirmed on the cluster: four candidate `tls.options` keys were reconciled and
   **none honoured**. So the missing curve knob is **not** something we failed to find — BNK does not
   expose one.
2. **`BNKGateway` is not a TLS object.** It is IP-address management (`ipv4BaseCidr`,
   `startAddress`/`endAddress`, `ingressConfig.defaultListenerNetworks`) — worth stating because the
   name invites the opposite assumption.
3. **`F5VirtualServer` and `F5BigClientsslSetting` are not BNK CRDs.** Neither appears in the BNK
   reference; they belong to the CNF/SPK lineage. Their presence on our cluster is incidental to the
   installed bundle, not a supported BNK path — which independently confirms §4C's conclusion that the
   `F5VirtualServer` route can never program here, and retires the idea that a better manifest would
   have fixed it.
## Activity program — 2026-09-30

Pinned build-box checks for one ELF with two entry programs. Check 05 passes
PREVAIL for both sections and executes both contexts through interpreter and
JIT with GCC and clang harnesses. It also checks signed target-set parsing with
ASan/UBSan. Check 08 repeats those checks on the final, signed artifact. It also
checks the new runtime's data layouts, legacy loading and old-parser refusal.

**MEASURED — live attempt 02:** the same 176,176-byte ELF runs at both entries
in isolated TMM build `f9a1ed8c8c54192e76e54bf7f1c59921b8a774c9`. Three request/reply
exchanges produce 24 JSON field records from six hook calls and 63 HTTP-handler
records. The collector replays all 87 records to a second cursor. Wrong-target
arming is refused. Both entry patches are observed and restored through `/proc`;
the process identity and restart count stay unchanged. The fixture is archived
and removed. SELF: traffic comparisons, counters, exporter and replay checks.
KERNEL: runtime identity and patch bytes. INDEPENDENT: PREVAIL. This original run
does not qualify request/reply association. The later
[combined-record result](#combined-activity-records-2026-09-30) qualifies the explicit
exchange contract for one worker and non-pipelined HTTP/1. Identity binding and
sustained data-path cost remain unqualified.
[Artifact and commands](env/ai-traffic/ACTIVITY-PROGRAM.md).

| Cached file | SHA-256 | Result |
| --- | --- | --- |
| `evidence/cache/activity-program-check-01.json` | `514a7584786abfd379d3f9c25ae449c2d0814360a39f64a67484852a9c0f8569` | Inlined JSON entry exceeds the 256-byte stack limit. |
| `evidence/cache/activity-program-check-02.json` | `bc8b3180a72d8723b4b0c4422c84d3561b44da3d3cb5c48e4912f52107642e03` | PREVAIL passes; native export lacks `ls_tp.h`. |
| `evidence/cache/activity-program-check-03.json` | `419119bad0339c0b1b418b8195e166af412c3815b6f5c9d3bce335f0294598b9` | uBPF refuses a subprogram ending. |
| `evidence/cache/activity-program-check-04.json` | `ef626c7d673b7de79cca02231e57757705a7ee01c79e4d2202d16964747d1fe6` | Block placement disabled; JIT output exceeds its default buffer. |
| `evidence/cache/activity-program-check-05.json` | `cd6840802f626ab703b13fc77f2a7647ac843859cb70ec100ed35d01ddcbef99` | Native two-context checks pass with a bounded 512 KiB JIT compiler buffer. |
| `evidence/cache/activity-program-check-06.json` | `8d1d0955b3e798341f884486a2fbb1f3677cb8bfb2f1fbea1a777115c45faf18` | New-build checks pass; signing export lacks `shield_abi.h`. |
| `evidence/cache/activity-program-check-07.json` | `fb4ea5df1dc8d6a85e41e497d43e5a627a5010a1b753ec87ed174a4b1f53a6d6` | Native, layout and regression checks pass; both bindings signed. ELF size is not yet checked. |
| `evidence/cache/activity-program-check-08.json` | `39930c81d460eaecabc45379f0f96ab525e8fb3e05c686622ac9483dfc5a0efc` | Final artifact passes all checks and the existing 256 KiB file limit. Debug stripping leaves executable sections unchanged. |
| `evidence/cache/activity-program-integration-01.json` | `8f589156a00216855ed4d7a176ce64c281bd86fe69d6c3b7f90dd51f04d43f31` | Three substrate files integrated; prescribed toolchain build passes. |
| `evidence/cache/activity-program-package-01.json` | `61d47bb42400734fb2351feadf962d0c87113c586a906ba17ea9adbca8888056` | Package/image checks pass; runtime SHA and image ID recorded. |
| `evidence/cache/activity-fixture-create-01.json` | `e938e71727d55cc925b5e867dd35102e5f993a2208940180d44ab460cc573de4` | Isolated fixture created with collector API mount; unrelated containers unchanged. |
| `evidence/cache/activity-program-live-01.json` | `eb9ace8c7d8d8d704db32065dbf65b415302d61477e3f767b8a9a7c4501e6c65` | Loader refuses ELF over 256 KiB; neither hook is armed. |
| `evidence/cache/activity-program-live-02.json` | `474beac275d2991a571447406e20a41e8c4fe93a63d3b0b253a51a796cdcb333` | Both hooks run together; exact fields, counters, export, replay and restored patch bytes pass. |
| `evidence/cache/activity-program-cleanup-01.json` | `0ed2d87b992365eb0b106d03b5ff82212c5fd7d3c6e2c7d1ff776f58dc97029b` | Archive checked before scoped removal; all slots inactive, both hooks restored and unrelated containers unchanged. |
| `evidence/cache/activity-program-evidence-20260930.tar.gz` | `b02ab6d4bdb64e6c64412106be99b1a26ba54bb698f2995eb190a3fa6919f1b0` | Both live attempts, Tao output and collector journals. No signing key or bytecode artifact. |
