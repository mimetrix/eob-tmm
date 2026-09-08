#!/usr/bin/env python3
"""check_tmmtop.py --- assert tmmtop's arithmetic, off-cluster.

WHY THIS EXISTS. tmmtop had no test at all. It was verified once by being pointed
at a live pod and producing plausible numbers, which is the weakest kind of
evidence: plausible is exactly what a broken rate calculation looks like. Every
value it prints is a DIFFERENCE between two samples, and the failure mode of a
difference is a number that is wrong rather than a number that is missing.

WHAT IS ASSERTED, and each one is a way the tool could lie rather than break:

  * `cycles_min` / `cycles_max` are ENVELOPES, not accumulators. Differencing them
    produces a per-second figure that means nothing and reads like a measurement.
  * a `gen` change means a reload happened between samples, so the delta spans a
    discontinuity and must be refused rather than reported.
  * a counter going BACKWARDS with `gen` unchanged is something the tool cannot
    model, and a negative rate printed as fact is worse than an error.
  * the interval comes from `time.monotonic()` around the whole read, so all slots
    in one snapshot share a clock; a non-positive interval must be refused.
  * a read failure on one slot must not remove the others from the table.

Run:  python3 substrate/check_tmmtop.py       (no cluster, no TMM, no loader)
"""
import importlib.machinery
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_loader(
    "tmmtop", importlib.machinery.SourceFileLoader(
        "tmmtop", os.path.join(HERE, "..", "env", "scripts", "tmmtop")))
tt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tt)

fails = 0


def ok(cond, msg):
    global fails
    print(("  ok    " if cond else "  FAIL  ") + msg)
    if not cond:
        fails += 1


def snap(mono, **slot0):
    return {"mono": mono, "read_span_s": 0.01, "wall": 0.0, "slots": {"0": dict(slot0)}}


print("check_tmmtop --- the arithmetic, with no cluster in sight\n")

print("rates: the ordinary case")
a = snap(100.0, armed=1, mode=1, gen=1, fired=1000, safe_returns=10, errors=0,
         cycles=50000, cycles_min=64, cycles_max=900)
b = snap(102.0, armed=1, mode=1, gen=1, fired=3000, safe_returns=20, errors=0,
         cycles=150000, cycles_min=64, cycles_max=1200)
r = tt.rates(a, b, {})["slots"]["0"]
ok(r.get("fired_per_s") == 1000.0, "fired 1000->3000 over 2.0 s -> 1000.0/s")
ok(r.get("safe_returns_per_s") == 5.0, "safe_returns -> 5.0/s")
ok(r.get("errors_per_s") == 0.0, "a counter that did not move -> 0.0/s, not absent")
ok("error" not in r, "no error on a clean pair")

print("\nenvelopes are reported, never differenced")
ok("cycles_min_per_s" not in r and "cycles_max_per_s" not in r,
   "cycles_min/max get NO _per_s --- differencing an envelope is meaningless")
ok(r.get("cycles_min") == 64 and r.get("cycles_max") == 1200,
   "they are reported as observed (min 64, max 1200 --- the LATER sample's values)")
ok(r.get("cycles_per_s") == 50000.0, "cycles itself IS an accumulator -> 50000.0/s")

print("\na reload between samples invalidates the row")
b2 = snap(102.0, armed=1, mode=1, gen=2, fired=50, safe_returns=0, errors=0, cycles=10)
r2 = tt.rates(a, b2, {})["slots"]["0"]
ok("error" in r2 and "gen changed" in r2["error"],
   "gen 1->2 -> error naming the reload, not a huge negative rate")
ok("fired_per_s" not in r2, "and NO rate is emitted for that row")

print("\na counter going backwards with gen unchanged is refused")
b3 = snap(102.0, armed=1, mode=1, gen=1, fired=5, safe_returns=0, errors=0, cycles=10)
r3 = tt.rates(a, b3, {})["slots"]["0"]
ok("error" in r3 and "went backwards" in r3["error"],
   "fired 1000->5 with gen unchanged -> error, not -497.5/s")
ok("fired_per_s" not in r3, "and no negative rate is printed as fact")

print("\nthe interval")
r4 = tt.rates(b, a, {})
ok(r4.get("error") == "non-positive interval",
   "samples in the wrong order -> refused, not a negative-rate table")
same = tt.rates(a, dict(a), {})
ok(same.get("error") == "non-positive interval", "a zero interval -> refused, no divide by zero")

print("\none bad slot must not take the others with it")
a5 = {"mono": 100.0, "read_span_s": 0.01, "wall": 0.0,
      "slots": {"0": dict(a["slots"]["0"]), "1": {"error": "no response"}}}
b5 = {"mono": 102.0, "read_span_s": 0.01, "wall": 0.0,
      "slots": {"0": dict(b["slots"]["0"]), "1": {"error": "no response"}}}
r5 = tt.rates(a5, b5, {})["slots"]
ok(r5["0"].get("fired_per_s") == 1000.0, "slot 0 still reports its rate")
ok("error" in r5["1"], "slot 1 reports its error")
ok(len(r5) == 2, "both rows present --- a failed read is a datum, not a deletion")

print("\nlabels")
r6 = tt.rates(a, b, {"0": "cve-shield"})["slots"]["0"]
ok(r6.get("label") == "cve-shield", "a declared label is used")
r7 = tt.rates(a, b, {})["slots"]["0"]
ok(r7.get("label") == "0", "an undeclared slot falls back to its number, never invents a name")

print("\nthe span is reported so a reader can judge the sample")
full = tt.rates(a, b, {})
ok(full.get("interval_s") == 2.0, "interval_s is reported")
ok("read_span_s" in full, "read_span_s is reported --- a long read skews every rate in the table")

print("\ntmctl parsing --- the panes read TMM's own stat tables, not shield counters")
{
}
# A fake tmctl on PATH, so the parsers are exercised without a pod. The point is the
# PARSE: tmctl's output is aligned columns for most tables and name/value pairs under
# -P, and reading one as the other is exactly the bug that made the first network pane
# report "no drop counters found" against a table that has four.
import subprocess as _sp, tempfile as _tf, textwrap as _tw
_d = _tf.mkdtemp()
_fake = os.path.join(_d, "tmctl")
open(_fake, "w").write(_tw.dedent("""\
    #!/bin/sh
    # $1=-d $2=blade then either TABLE or -P TABLE
    if [ "$3" = "-P" ]; then
      case "$4" in
        tmm_stat) printf 'polls 1000\\nidle_polls 250\\ndropped_packets 7\\nincoming_packet_errors 2\\noutgoing_packet_errors 0\\nconnection_memory_errors 0\\n' ;;
      esac
      exit 0
    fi
    case "$3" in
      tmm/physmem) printf 'name        used      avail\\n------- -------- ----------\\nphysmem 15745024 1564475392\\n' ;;
      tmm/umem_usage_stat) printf 'name        used allocated max_allocated fail_allocs\\n----------- ---- --------- ------------- -----------\\numem_ok     2304      8192          8192           0\\numem_bad    4096     16384         16384          42\\n' ;;
    esac
    """))
os.chmod(_fake, 0o755)

rows = tt.read_tmctl("tmm/physmem", _fake)
ok(len(rows) == 1 and rows[0]["used"] == 15745024 and rows[0]["avail"] == 1564475392,
   "aligned columns parse, and integers become integers")
ok(rows[0]["name"] == "physmem",
   "a name column stays a STRING --- silently becoming 0 is worse than staying text")

piv = tt.read_tmctl_pivot("tmm_stat", _fake)
ok(piv.get("dropped_packets") == 7 and piv.get("polls") == 1000,
   "-P name/value pairs parse")

m = tt.mem_snapshot(_fake)
ok(m["physmem"]["used"] == 15745024, "mem pane reads physmem")
ok(m["caches_total"] == 2, "it counts every cache")
ok(len(m["caches_failing"]) == 1 and m["caches_failing"][0]["name"] == "umem_bad",
   "it lists ONLY caches that failed an alloc --- a large cache is normal, a failing one is not")

n = tt.net_snapshot(_fake)
ok(n.get("dropped_packets") == 7 and n.get("outgoing_packet_errors") == 0,
   "net pane reads the drop counters, including the zeros")
ok("error" not in n, "and reports no error when the table is readable")

sc = tt.sched_snapshot(_fake)
ok(sc["polls"] == 1000 and sc["idle_polls"] == 250, "sched pane reads polls/idle_polls")
ok(sc["idle_fraction_since_boot"] == 0.25,
   "idle fraction is computed, and named 'since boot' --- two accumulators make a "
   "lifetime average, not 'idle now'")

print("\nthe panes fail SOFT --- a missing tmctl must not take the slot table with it")
ok(tt.read_tmctl("tmm/physmem", "/nonexistent/tmctl") == [],
   "no tmctl -> empty list, no exception")
ok("error" in tt.mem_snapshot("/nonexistent/tmctl")["physmem"],
   "mem pane reports the failure instead of printing zeros")
ok("error" in tt.net_snapshot("/nonexistent/tmctl"), "net pane reports the failure")
ok("error" in tt.sched_snapshot("/nonexistent/tmctl"), "sched pane reports the failure")

print("\nhuman() units")
ok(tt.human(1024) == "1.0 KiB" and tt.human(15745024) == "15.0 MiB",
   "binary units, labelled KiB/MiB --- a memory figure off by 2.4% gets argued about")
ok(tt.human("x") == "x", "a non-integer passes through rather than crashing the pane")

print("\n%s (%d failure%s)" % ("all assertions passed" if not fails else "*** FAILED",
                              fails, "" if fails == 1 else "s"))
sys.exit(1 if fails else 0)
