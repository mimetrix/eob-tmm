# JSON initialization-completion qualification

**2026-09-29 — MEASURED source, compiled-code and admission checks. None of the
tested candidates qualifies under the existing admission rules.** The two return-hook candidates are refused. The
forwarding path does not supply the required completion witness. The saved-evidence
verifier passes on the build box and locally. Initialization completion and local
lifecycle remain unvalidated. [Evidence](../../SOURCES.md#json-initialization-completion-qualification-2026-09-29).

**Current limit:** [ENTRY-SNAPSHOT.md](ENTRY-SNAPSHOT.md) adds production capture,
native bytecode tests and a built/packaged TMM. Live admission is refused. The
new full-width unwind check exposed three imports in both packaged binaries.
The enum-return positive control below passed the old, defective check. Its
unwind-clear result is falsified; the conditional source proof is separate.
[Correction and receipts](../../SOURCES.md#production-entry-snapshots-2026-09-29).

**Earlier native result:** [VOID-COMPLETION.md](VOID-COMPLETION.md) tests the
frame-bound entry-snapshot adapter with the unchanged return machinery. Both
compiler variants pass 24 cases and 1,100 observed returns. The native mechanism
question is resolved; production entry-snapshot integration is the next work.
This does not reverse the existing admission refusal or establish live lifecycle.

The contract below was registered as **IDEA** before the checks. Its objective is
an observation that establishes completion of JSON-context initialization. A live
probe follows only if the qualification identifies a supported observation point.

## Starting limits

[JSON-LIFECYCLE.md](JSON-LIFECYCLE.md) measures handler, completion and reset
entries. It does not establish completed initialization. Eleven unavailable
handler records invalidate the full recorded window. Its storage tags survive
address reuse and have no lifetime meaning.

The pinned source puts initialization and cleanup inside `hud_json_handler`.
A disabled-context branch can bypass those effects. Reset also releases message
state without ending the context's lifetime.
[Existing source evidence](../../SOURCES.md#message-scope-qualification-2026-09-29).

## Qualification contract

1. Recheck the recorded TMM source, executable, debug companion and hook index on
   the build box. Save the admission script and its tool versions with the result.
2. Run the existing return-hook admission gate for `hud_json_handler`,
   `json_filter_reset_ingress_for_reuse` and the previously admitted
   `tmm_json_value_get_string` control. Retain refusals as results. Do not change
   admission rules to make a candidate pass.
3. Check whether `hud_json_init_scb` and `hud_json_uninit_scb` have supported
   standalone entries. A source function name or an inline debug entry is not
   sufficient.
4. Trace the compiled initialization path through its final state write and the
   subsequent forwarding path. Check the disabled bypass as well. Determine
   whether a padded forwarding entry preserves the original node and can identify
   the invocation that performed initialization.
5. Before a return-side memory read, qualify the lifetime of the pointed-to node
   and context across forwarding. Saved entry arguments do not keep storage alive.
6. Keep separate decisions for supported attachment, completion semantics and
   coverage. A successful attachment check alone cannot validate a lifecycle.

No TMM source edits, admission-rule changes, interior instruction patches or live
fixture creation are part of this first qualification. If a supported point is
found, register its exact fields, read limits and negative tests before building.

## Falsifiers

Reject the direct return-hook candidate if the pinned admission gate refuses it,
the return type is not supported, or unwind checks are incomplete. Reject a
forwarding-entry shortcut if it can follow the disabled bypass, loses the original
node, or lacks an invocation-specific link. A later field value alone cannot
prove which earlier path ran. Reject post-return dereferences unless the storage
lifetime is qualified.

A negative qualification is a completed result for this gate. It must name the
rejected candidate and the remaining work. It must not claim that initialization
can never be observed. Local lifecycle, request scope, common owner lifetime,
message association and authenticated identity remain unvalidated.

```text
BUILD BOX — pinned sources + binary + debug data
  -> existing admission checks + compiled-path inspection
  -> supported observation point, or a documented refusal
NEXT GATE, ONLY IF QUALIFIED — bounded probe contract -> verify -> isolated traffic
LATER — completion witness + end/reuse rules + coverage -> possible local lifecycle
```

## Result and candidate decisions

The checks use build `ca69b84f4f5c9e225813b2ed3997c59f18ba2a31`. Binary SHA-256:
`05d17517531d99b26eb9e8f00f5b5326f660b5bef492226c9555368b887a9611`.
The debug companion has the same build ID. TMM source revision:
`e2104734a940a099a9190eb84bfbea01fb4b81d4`. The source-status check covers only the
inspected paths. It does not assert a clean TMM tree.

| Candidate | Observed result | Decision |
|---|---|---|
| Return from `hud_json_handler` | Old `exit_admit.py` refuses the void return type in both captures. Its unwind-clear result was later falsified (§39). | Rejected. |
| Return from `json_filter_reset_ingress_for_reuse` | Same refusal in both captures. Reset also does not end context lifetime. | Rejected. |
| Return from `tmm_json_value_get_string` | Old gate admits the enum return in both captures. Corrected full-width unwind inspection now refuses it. | Historical positive control was defective; not an initialization witness. |
| Standalone `hud_json_init_scb` or `hud_json_uninit_scb` | No matching symbol or hook-index entry in the captured candidates. | No standalone attachment identified. |
| Entry to `xbuf_embed_init` | Binder refuses its displaced-instruction entry. Its call also precedes the final initialization write. | Rejected on attachment and completion grounds. |
| Forwarding entry | Disabled and initialized paths share forwarding. The compiled initialization path calls the next node's handler directly. | No qualified original-node, invocation-specific completion witness. |
| Entry to the orbit handler wrapper | The wrapper later calls `orb->handler`. | Entry precedes the wrapped handler's effects. |
| Read saved node/context pointers after return | Entry arguments are copied, but storage lifetime across forwarding has not been qualified. | No post-return dereference qualified. |

These are **MEASURED qualification results**, not live initialization results.
TOOL witnesses supply source, type, symbol and instruction output. SELF witnesses
supply the admission policy and saved-evidence checks. The verifier checks 48 source
snapshots across two captures, seven source references and 15 instruction locations.
The candidates were not loaded or armed in this gate.

### Compiled path that rejects the forwarding shortcut

`HUDEVT_FLOW_INIT` is `0x39`. Its jump-table entry at `0x22ae328` contains
`0xd94c48`, the initialization path. That path clears context storage and calls
`xbuf_embed_init` at `0xd94c7e`. The final `f_send_egress` write is at `0xd94c87`.

Forwarding then reaches `0xd94c0d`. This instruction loads `node->above` from
offset `0x18`. At `0xd948b1`, the next node becomes the first argument. The indirect
call at `0xd948b4` invokes that node's handler. This path does not call the indexed
`hud_orbit_handle_upper` entry. A padded copy elsewhere does not cover an inline
copy here.

The disabled check at `0xd94169` can bypass initialization. For the same event,
that branch reaches the shared forwarding path through `0xd953fa`, `0xd94d90`
and `0xd94c8e`. Thus arrival at the next handler alone does not prove that the
previous handler initialized its context. Source lines 1018–1026 and 1378–1379
in the captured `json_filter.c` show the same distinction. This is a compiled-path
counterexample, not a live disabled-path test.

### Retained records

Discovery 01 retains the first admission results. Its handler disassembly stopped
at `0xd95600`, before the symbol end at `0xd95679`. Discovery 02 extends the range
to `0xd95680` and adds the jump-table, layout and binder checks. Both remain cached.
Check 01 passes against both records on the build box.

The first copy of discovery 02 timed out and had a different SHA-256. A complete
copy with a longer timeout matches the authoritative file. The authored preflight
record retains that stop and the three `ask` results, each **NO RECORD**.

## Reproduce the qualification

From this repository:

```bash
python3 env/ai-traffic/json_initialization_verify.py
python3 env/ai-traffic/json_initialization_verify.py --export
```

The export contains candidate decisions, source references and checked instructions.
It contains no live initialization records. The verifier pins the two captures and
the current discovery/admission sources. Historical Markdown remains embedded in
the captures; later result text does not change that historical contract.

For a fresh capture on the prepared build box, stage the discovery script and this
document beside the existing boundary receipt. Select an unused output name:

```bash
python3 /home/starin/eob-config-20260925/json_initialization_discover.py \
  --boundary /home/starin/eob-config-20260925/json-lifecycle-discovery-01.json \
  --output /home/starin/eob-config-20260925/json-initialization-discovery-03.json
```

Review a fresh capture before changing the saved verifier's pins. A changed binary,
tool or source needs a new qualification. The current verifier proves consistency
with retained evidence; it does not inspect a running TMM.

## Remaining work

### What the source already establishes

The void-return refusal is an admission-policy restriction. In the captured
`exit_admit.py`, lines 129–130 reject `void` because there is no return value.
In `ls_fexit.c`, lines 93–99 save the return-address slot and original arguments.
Lines 117–129 match the returning invocation by that slot. A successful match
does not depend on a meaningful return value. This explains the mechanism; it
does not change the recorded admission refusal or establish live void-hook support.

The JSON source gives a conditional completion proof. For `HUDEVT_FLOW_INIT`,
if the context is present and its disabled flag is clear at the handler's guards,
the handler calls `hud_json_init_scb` before forwarding. The helper's final write
sets `f_send_egress`. A normal return from that same invocation therefore follows
completion of initialization. See captured `json_filter.c`, lines 531–539,
1014–1026 and 1378–1396, in the
[existing receipts](../../SOURCES.md#json-initialization-completion-qualification-2026-09-29).

This determines the candidate's required information:

```text
ENTRY: establish initialization event + present context + enabled context
       save those conditions with the exact invocation
MATCHED NORMAL RETURN: emit that initialization completed for that invocation
```

The current exit frame saves argument values, not the pointed-to context's entry
state. That missing entry-state capture is implementation work. A completion-only
record need not read the context after return or interpret the return register.
It proves a past action, not that the context remains alive after forwarding.
End/reuse ordering and missing observations still need separate treatment.

The [native completion-only test](VOID-COMPLETION.md) now passes, including nested
calls, skipped returns, capacity and an unreadable post-return context. Implement
the host entry-snapshot interface next. Its admission must distinguish completion
from return-value observation and preserve the ordinary hook contract. The native
adapter does not yet supply that production integration.

The integrated program still needs bytecode verification and isolated live tests.
Completed initialization, end/reuse rules and coverage must qualify before a local
lifecycle can be claimed. Common owner lifetime, message association and
authenticated identity remain separate work.
