# Request-correlation gaps

**MEASURED, 2026-09-28: reported gaps invalidate the whole result window.**
All 150 live requests completed normally. Fresh recovery restored matching for
new connections; a retained connection stayed unknown. The fixture is removed.
[Receipts and hashes](../../SOURCES.md#controlled-correlation-gaps-2026-09-28).

Registered as IDEA before implementation. The build and live receipts retain
that contract, including the explicit limit on silent-gap detection.

Test the remaining gap in [CORRELATION.md](CORRELATION.md): both cleanup and
initialization can be missed while a stored parser entry remains active.
Also test stopping/restarting observation and exhausting the tracking bounds.

## Falsifiers

- A known gap must make every attempted join in that window unknown. Reattaching
  hooks must not restore trust in retained state. This rule applies even if event
  sequence numbers and counters agree.
- A repeated address after omitted cleanup/initialization must not be described
  as a validated uninterrupted parser lifetime. Test this with four real native
  VMs sharing the pinned host maps. Use distinct request markers before/after reuse.
- No tracking-limit diagnostic may acquire an actor. Exceed the candidate limit
  (127 lifetimes) and lifetime limit (256 initializations). Check no old candidate
  escapes after capacity refusal. Keep every attempted output accounted for.
- Recovery requires all programs disabled/revoked, new loaded instances, a new run
  token and checked fresh state. Test positive requests after recovery. Also keep
  a connection open across the restart: it must stay unknown without a new birth.
- Native interpreter and JIT results must agree. Live traffic must still receive
  its expected authenticated responses. Require no new VM errors or selections,
  no reported output drops, stable TMM identity and restored hook bytes.

## Method and limits

Keep the four signed programs from correlation build 02. First retain a native
counterexample to treating complete output as complete hook coverage. Add a
collector-side window guard that becomes permanently unavailable after a known
gap. Only a new window with fresh state can recover. Keep the previous join as
the bounded matching step; it cannot itself know that a hook was detached.

The fixture controller supplies the gap notification before its detach command.
This is a trusted, single-controller experiment. It does not detect silent hook
bypass, an unreported controller change, a lost controller log, or a collector
restart that restores stale state. An absent coverage record must be refused.
Do not claim automatic recovery from an unobservable gap.

Live tests use the isolated SSA fixture and pinned repaired image. Exercise a
baseline window, a window with both boundary hooks detached during connection
close/reopen, a full observation pause/resume, a capacity window, and recovery
with a retained old connection plus fresh connections. A live address-reuse
counterexample is a result only if the records actually show reuse; native reuse
is controlled and is a separate result. New candidate/lifetime capacity is not
request capacity: response parsing also consumes observed lifetimes.

Keep a complete ledger for each window. Never choose its rows by the marker the
observer extracted. Compare clients and authority independently after matching.
Any controlled gap invalidates the whole window, including earlier observations.
Do not publish provisional identities before the window closes.

## Evidence

Retain exact sources, contracts, tool and object identities, failed attempts,
native event traces, live records, commands and kernel witnesses. Archive the
fixture evidence with checked hashes before removal. Register results and limits
in `GROUND_TRUTH.md` and `SOURCES.md`. No data-path cost claim is part of this test.

## Result

### What changed

`gap_window.py` adds a collector-side guard around the existing matching code.
The fixture controller reports a break before detaching a hook. That window then
stays unavailable, even after reattachment. Matches are available only after the
window closes with the same four loaded program instances. Missing fresh-window
evidence, a changed run token, changed instances or exhausted capacity also refuse
attribution. A new window requires a full disable/revoke/reload and a new run token.

This guard is separate from the BPF programs. The test reuses the four signed
programs from correlation build 02. It does not change the TMM binary or add a
host-enforced coverage guarantee. Use this guarded path for controlled gaps;
the earlier `correlation_suite.py` remains the recorded no-gap workload test.

```text
CONTROLLER — off the TMM data path
  Load fresh instances + run token → begin window
  Before any detach → mark that window unavailable permanently
                              │
TMM — data path               │
  Four existing monitors → bounded records + counters
                              │
DESTINATION                   │
  Validate complete request → authority ledger
                              │
COLLECTOR — off the TMM data path
  Close window → check controller state, records and ledger → match or unknown
```

### Native result

Pinned PREVAIL rechecks all four final objects. Four real VMs share the pinned
host maps in both interpreter and JIT tests. With cleanup and initialization
omitted at a reused address, two different simulated object lifetimes retain
one observed lifetime number. The output sequence has no gap. The old consumer
accepts that native trace as two matches under the same lifetime. The new guard
leaves both unknown after a reported break.

This is a stale-lifetime counterexample, **not a wrong-agent result**. The native
trace still extracts distinct A/B markers correctly. Its ledger is synthetic.
Seven guard checks per mode cover an unsealed window, a known break, attempted
reopening, absent coverage evidence, changed instance, capacity and changed run.

The same native test admits lifetimes 1–127 for extraction and refuses 128 onward.
It fills 256 distinct lifetime entries and refuses initialization 257, including
reuse of an old address after the limit. No old marker is emitted after refusal.
A fresh reset rejects an old object until initialization is observed, then reads
the new marker correctly. The output sink is substituted; these are SELF checks.

### Live result — `gap-live-02`

| Window | HTTP requests | Header observations | Guarded result |
|---|---:|---:|---|
| Baseline | 2 | 2 | Two accepted-operation matches |
| Miss cleanup and initialization | 2 | 2 | Both unknown; stale lifetime reuse is observed across separately opened connections |
| Pause all four hooks, then resume | 3 | 2 | Both observations unknown; one request deliberately has no observation |
| Exhaust tracking limits | 140 | 140 | All unknown, including earlier valid candidates in that window |
| Full reload with fresh state | 3 | 3 | Two fresh-request matches; one request on the retained connection stays unknown |

All 150 requests are authenticated and accepted by the fixture authority. The
149 header observations yield four accepted-operation matches and 145 unknowns.
These counts describe deliberate failure tests, not normal-traffic coverage.
The whole-window rule intentionally discards earlier valid matches after a break.

All 1,023 calls reconcile with records: 288 initializations, 149 client-parser
returns, 288 cleanups and 298 candidate-reader calls. Each window has a new run
token and four new loaded instances. Event sequences restart at one. Reversing
ledger order preserves the guarded results.

The capacity window reaches 280 initialization calls: 256 observed births and
24 capacity refusals. It records 129 candidate-limit diagnostics. It exhausts
the admission budgets; it does not prove that all live map entries held distinct
addresses. The distinct-address full-table check is the native test above.

The old consumer also refuses both observations in the **live** boundary-gap
window because other required evidence is missing. Do not present that live run
as a wrong-agent assignment by the old consumer. The native trace separately
shows why complete output alone cannot prove continuous boundary observation.

KERNEL reads show seven CALL/NOP cycles at initialization and cleanup, and six
at client-parser return and candidate-reader entry. All four sites are restored.
Process/binary identity is stable and restart count is zero. No output drop,
output refusal, new VM error or verdict selection is reported. Client, authority,
controller and program records are SELF witnesses; PREVAIL is INDEPENDENT.

### Limits after this result

- `controlled_gap_guard_validated=true`; `request_scope_validated=false`.
  The controller must report each break before it changes attachment state.
- A silent hook bypass, unreported control change, missing controller history or
  stale collector restart is still outside the validated scope. An event sequence
  cannot reveal invocations that never reached a hook.
- Recovery uses the existing full reload path and new instances. Changing only
  the run token or resuming old hooks is not qualified recovery.
- Results are closed-window, not provisional streaming identities. The guard may
  discard valid observations with the rest of an invalid window.
- Production ledger provenance, other parser paths, HTTP/2, multiple workers,
  sustained output pressure, differentiated visibility and data-path cost remain open.

### Final checks and cleanup

Live attempt 01 stopped at a lint warning before attachment: the result-file write
did not specify its encoding. The corrected write uses UTF-8. The failure and
original source remain cached. Attempt 02 passes Black, scoped pylint, fixture
JSON and Tao XML checks. Convention/refactor lint rules and broad cleanup catches
are excluded; this is not a full style-compliance result.

Snapshot 01 checks live-source hashes, Python/shell syntax and disabled slots
5–8. Configuration status refuses for all four slots. Cleanup checks the same
process/binary, four restored hook sites and all 12 inactive loader slots.
It archives and checks 25 evidence files, then removes two containers, two
networks and four volumes. The toolchain container retains its identity/state.

## Repeat

Use the pinned build VM and staging paths in [CORRELATION.md](CORRELATION.md#repeat-this-bounded-test).
Keep the checked `correlation-build-02` artifacts available. Stage the new gap
scripts and `substrate/check_correlation_gaps.c`, plus all imported fixture modules.
Use unused names. These commands run on the build VM:

```sh
python3 /home/starin/eob-config-20260925/gap_build.py \
  --output /home/starin/eob-config-20260925/gap-build-next
python3 /home/starin/eob-config-20260925/lifetime_fixture.py create \
  --output /home/starin/eob-config-20260925/gap-create-next.json
python3 /home/starin/eob-config-20260925/lifetime_live_run.py \
  --run gap-live-next --artifact-dir gap-build-next --suite gaps \
  --output /home/starin/eob-config-20260925/gap-live-next.json
python3 /home/starin/eob-config-20260925/lifetime_snapshot.py \
  --live /home/starin/eob-config-20260925/gap-live-next.json \
  --output /home/starin/eob-config-20260925/gap-snapshot-next.json
python3 /home/starin/eob-config-20260925/lifetime_fixture.py archive-cleanup \
  --live /home/starin/eob-config-20260925/gap-live-next.json \
  --archive /home/starin/eob-config-20260925/gap-evidence-next.tar.gz \
  --output /home/starin/eob-config-20260925/gap-cleanup-next.json
```

Run each step only after the previous required checks pass. Retain failures and
use a new attempt name. Cleanup requires a successful receipt for the same fixture.
