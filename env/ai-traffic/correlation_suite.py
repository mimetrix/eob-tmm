"""Read bounded candidate values and challenge a closed-window fixture join."""
import asyncio
from collections import Counter
import copy
import json
import os
from pathlib import Path
import struct

import tao
import tao.runner
import tao.test_types

from attribution import Client
from correlation_join import join
from icap_suite import BACKEND, VIP, configure
import lifetime_suite
from lifetime_suite import FIELDS, PROGRAMS, ParserLifetime
from config_suite import PORT
from request_scope_suite import ScopeClient

# This suite runs in its own Tao process. All four programs share one registry.
PROGRAMS["candidate"] = (8, 4, "http_parse_headers")
RAW_FIELDS = (
    "magic",
    "abi",
    "run",
    "sequence",
    "lifetime",
    "attempt",
    "failures",
    "flags",
    "path_code",
    "total",
    "reserved",
    "nonce_bytes",
)


class CandidateClient(ScopeClient):
    """Add hostile and delegated requests without changing the traffic counts."""

    async def request(self, name, *args, **options):
        actor, path, method, expected_actor = args
        if name == "new-connection-0":
            options["nonce"] = "short-nonce"
        elif name == "new-connection-1":
            options.update(key_actor="agent-A", status=401)
            expected_actor = None
        elif name == "new-connection-2":
            options["claimed"] = "agent-B"
        elif name == "new-connection-3":
            method = "unsupported"
            options["status"] = 403
        elif name == "new-connection-5":
            parent = next(
                r["operation"]
                for r in self.test.authority.ledger
                if r["accepted"] and r["actor"] == "agent-B"
            )
            path, method = "/delegate", "delegate"
            options["params"] = {
                "parent": parent,
                "recipient": "agent-A",
                "scope": ["tools/call"],
            }
        elif name == "new-connection-6":
            options.update(delegation=self.test.grant, originator="agent-B")
        response = await super().request(
            name, actor, path, method, expected_actor, **options
        )
        if name == "new-connection-5":
            self.test.grant = response["grant"]
        return response


class Correlation(ParserLifetime):
    """Retain all four streams and keep general request scope unvalidated."""

    def __init__(self, output):
        super().__init__(output)
        self.candidates = []
        self.stream_sequence = 0
        self.grant = None
        self.result.update(candidates=self.candidates, bounded_join_validated=False)

    async def client(self, observed=True):
        reader, writer = await asyncio.open_connection(VIP, PORT)
        value = (
            CandidateClient(reader, writer, self)
            if observed
            else Client(reader, writer, self.authority.keys, self.result["clients"])
        )
        self.clients.append(value)
        return value

    async def start(self):
        await super().start()
        await self.attach("candidate")

    async def drain(self, label):
        row = await self.run(
            "/work/ls_drain", "--segment", "/run/ls-stream/ls_tp_ring", "--once"
        )
        transport = [json.loads(line) for line in row["stdout"].splitlines()]
        self.result["batches"].append({"label": label, "transport": transport})
        assert "0 drop(s) seen" in row["stderr"]
        values = []
        for item in transport:
            assert item["hook"] == "prog"
            raw = item["slot"] == 8
            event = dict(
                zip(
                    RAW_FIELDS if raw else FIELDS,
                    struct.unpack(
                        "<II5Q4I32s" if raw else "<II6QII", bytes.fromhex(item["data"])
                    ),
                )
            )
            assert event["magic"] == (0x43414E44 if raw else 0x4C494645)
            assert event["abi"] == 1 and event["run"] == self.run_token
            self.stream_sequence += 1
            assert event["sequence"] == self.stream_sequence and not event["failures"]
            if raw:
                event["nonce"] = event.pop("nonce_bytes").decode("ascii").rstrip("\0")
                event["path"] = {1: "/mcp", 2: "/a2a", 3: "/delegate"}.get(
                    event["path_code"]
                )
                assert event["flags"] in (0, 1, 4, 8, 64), event
                if event["flags"] != 1:
                    assert not event["nonce"] and event["path"] is None
                self.candidates.append(event)
                continue
            assert item["slot"] == {1: 6, 2: 5, 3: 7}[event["kind"]]
            assert event["flags"] in (0, 32, 256), event
            self.events.append(event)
            values.append(event)
            if event["kind"] == 1:
                assert event["lifetime"] not in self.active
                self.active.add(event["lifetime"])
            elif event["kind"] == 3 and event["lifetime"]:
                self.active.remove(event["lifetime"])
        return values

    def reconcile(self):
        # Reuse the prior three-hook checks without treating raw reads as ends.
        fourth = lifetime_suite.PROGRAMS.pop("candidate")
        try:
            super().reconcile()
        finally:
            lifetime_suite.PROGRAMS["candidate"] = fourth
        first, last = self.result["counter_start"], self.result["counter_end"]
        accounting = {}
        for name in PROGRAMS:
            accounting[name] = last[name]["fired"] - first[name]["fired"]
            assert last[name]["gen"] == first[name]["gen"]
            assert last[name]["errors"] == first[name]["errors"]
            assert last[name]["safe_returns"] == first[name]["safe_returns"]
        assert accounting["candidate"] == len(self.candidates)
        accounting.update(drops=0, errors=0, selections=0)
        unarmed = {
            c["result"]["attempt"]
            for c in self.result["clients"]
            if c["case"] in ("before-attach", "after-disarm")
        }
        ledger = [r for r in self.authority.ledger if r["attempt"] not in unarmed]
        result = join(self.events, self.candidates, ledger, accounting)
        assert result == join(
            self.events, self.candidates, list(reversed(ledger)), accounting
        )
        assert Counter(r["status"] for r in result) == {
            "attributed": 42,
            "rejected": 1,
            "unknown": 8,
        }, result
        assert Counter(r["reason"] for r in result if r["status"] == "unknown") == {
            "missing_parser_initialization": 3,
            "ambiguous_candidate": 3,
            "unavailable_candidate": 1,
            "no_authentication_evidence": 1,
        }
        by_attempt = {r["attempt"]: r for r in ledger}
        excluded = {
            "before-attach",
            "after-disarm",
            "late-attach",
            "missing-init",
            "init-restored-existing-connection",
            "new-connection-0",
        }
        expected_values = Counter(
            (c["result"]["path"], c["nonce"])
            for c in self.result["clients"]
            if c["case"] not in excluded
        )
        assert (
            Counter((c["path"], c["nonce"]) for c in self.candidates if c["flags"] == 1)
            == expected_values
        )
        for row in result:
            if row["status"] != "unknown":
                matched = by_attempt[row["authority_attempt"]]
                assert row["actor"] == matched["actor"]
                if row["status"] == "attributed":
                    assert row["operation"] == matched["operation"]
        # Independent extraction checks use expected client/authority records only
        # after matching. They are not inputs to the observer or to candidate selection.
        raw_by_interval = {
            (r["lifetime"], r["attempt"]): r for r in self.candidates if r["flags"] == 1
        }
        for phase in self.result["phases"]:
            if "attempt" not in phase or phase["expect_unknown"]:
                continue
            parsed = [e for e in phase["events"] if e["kind"] == 2 and e["value"] == 0]
            assert len(parsed) == 1
            e = parsed[0]
            raw = raw_by_interval.get((e["lifetime"], e["attempt"]))
            if phase["name"] == "new-connection-0":
                assert raw is None
            else:
                expected = by_attempt[phase["attempt"]]
                assert raw and (raw["path"], raw["nonce"]) == (
                    expected["path"],
                    expected["nonce"],
                )
        negatives = []
        for label, life, raw, rows, counts in (
            ("missing-output", self.events, self.candidates[:-1], ledger, accounting),
            ("missing-ledger", self.events, self.candidates, ledger[:-1], accounting),
            (
                "duplicate-ledger",
                self.events,
                self.candidates,
                ledger + [ledger[0]],
                accounting,
            ),
            (
                "reported-loss",
                self.events,
                self.candidates,
                ledger,
                {**accounting, "drops": 1},
            ),
        ):
            failed = join(life, raw, rows, counts)
            assert failed and all(r["status"] == "unknown" for r in failed)
            negatives.append(label)
        changed = copy.deepcopy(self.candidates)
        changed[0]["sequence"] = True
        assert all(
            r["status"] == "unknown"
            for r in join(self.events, changed, ledger, accounting)
        )
        negatives.append("invalid-sequence")
        self.result.update(
            join=result,
            accounting=accounting,
            join_negative_checks=negatives,
            bounded_join_validated=True,
            request_scope_validated=False,
        )
        self.result["summary"].update(
            candidate_calls=len(self.candidates),
            all_events=self.stream_sequence,
            attributed=42,
            authority_rejected=1,
            unknown=8,
        )


async def correlation_test(log, _config):
    """Keep all failures and try every cleanup action."""
    test = Correlation(Path(os.environ["ICAP_RESULT"]))
    with test.output.open("x") as output:
        try:
            test.result["acknowledgements"] = await configure(log, port=PORT)
            async with await asyncio.start_server(test.authority.serve, BACKEND, PORT):
                await test.exercise()
                test.reconcile()
            test.result["passed"] = True
        except BaseException as error:
            test.result["error"] = repr(error)
            raise
        finally:
            try:
                closed = await asyncio.gather(
                    *(c.close() for c in test.clients), return_exceptions=True
                )
                await test.stop()
                assert not [c for c in closed if isinstance(c, BaseException)]
            except BaseException as error:
                test.result.update(passed=False, cleanup_error=repr(error))
                raise
            finally:
                json.dump(test.result, output, indent=2)
    return tao.Result.PASS


def publish_tests():
    """Expose this bounded fixture experiment."""
    return [
        tao.test_types.DockerBaseTest2("request correlation gate", correlation_test)
    ]
