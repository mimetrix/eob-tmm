#!/usr/bin/env python3
"""Explore what can be armed in the RUNNING binary --- the pre-flight for a live demo.

WHY THIS EXISTS. The strongest moment in the demo is handing the audience the choice of
target: "name a function." Its weakness is that a freely chosen name usually arms and then
never fires, because the demo's traffic does not reach it --- and "armed, 0 fires" reads as
failure when it is actually the reachability limit doing its job.

This answers the question BEFORE arming, so a chosen name yields a sentence either way.

Reads the hook index baked into the image and the pod's own tooling. Everything runs through
`kubectl exec` of what is ALREADY THERE (python3, cat). Nothing is copied into the container
--- that is the hack the baked-in tooling exists to avoid.

    bnk-explore-hooks.py stats               what the index says about this build
    bnk-explore-hooks.py search <pattern>    matching names, and whether each is armable
    bnk-explore-hooks.py explain <name>      the pre-arm verdict for one name
    bnk-explore-hooks.py suggest [prefix]    armable, unambiguous names grouped by prefix
    bnk-explore-hooks.py probe <name>...     ARM in MONITOR, wait, report which fired,
                                             then disarm. The live reachability answer.

Environment: POD (default: first Running f5-tmm pod), KUBECTL (default: kubectl).
"""
import collections
import os
import subprocess
import sys

KUBECTL = os.environ.get("KUBECTL", "kubectl")
INDEX_IN_POD = "/usr/share/ls/hook-index.tsv"


def sh(args):
    return subprocess.run(args, capture_output=True, text=True)


def pods():
    r = sh([KUBECTL, "get", "pods", "-l", "app=f5-tmm", "--no-headers"])
    return [l.split()[0] for l in r.stdout.splitlines()
            if len(l.split()) > 2 and l.split()[2] == "Running"]


def pod():
    if os.environ.get("POD"):
        return os.environ["POD"]
    ps = pods()
    if not ps:
        sys.exit("*** no Running f5-tmm pod. Nothing to explore.")
    return ps[0]


def load_index(p):
    """Pull the index out of the pod ONCE. Every query after this is local."""
    r = sh([KUBECTL, "exec", p, "-c", "f5-tmm", "--", "cat", INDEX_IN_POD])
    if r.returncode != 0 or not r.stdout:
        sys.exit("*** could not read %s from %s.\n"
                 "    An image without the index cannot arm by name at all."
                 % (INDEX_IN_POD, p))
    meta, syms = {}, collections.defaultdict(list)
    for line in r.stdout.splitlines():
        if not line:
            continue
        if line.startswith("#"):
            parts = line[1:].split("\t")
            if len(parts) >= 2 and parts[0] != "name":
                meta[parts[0]] = parts[1]
            continue
        f = line.split("\t")
        if len(f) >= 3:
            syms[f[0]].append({"at": f[1], "how": f[2],
                               "pad": f[3] if len(f) > 3 else "-",
                               "disp": f[4] if len(f) > 4 else "0"})
    return meta, syms


def verdict(name, entries):
    """The pre-arm answer. Every branch is a sentence that can be said out loud."""
    if not entries:
        return ("NOT ARMABLE",
                "not in the index --- it does not exist in this build, or the optimiser "
                "inlined or folded it away, or it lives in a separately built component "
                "that never saw the padding flag")
    if len(entries) > 1:
        return ("AMBIGUOUS",
                "%d entries under this name --- a file-scope static repeated across "
                "translation units, an .isra/.constprop clone, or an assembler label. "
                "Arming refuses rather than picking one" % len(entries))
    e = entries[0]
    if e["how"] == "pad":
        return ("ARMABLE",
                "padded at offset %s --- five reserved nops become a call, and no "
                "instruction is displaced" % e["pad"])
    return ("NEEDS DISPLACEMENT",
            "no compiler pad. Its first %s bytes are position-independent, so it COULD be "
            "armed by copying them and jumping --- but that path is designed and not built, "
            "so arming refuses today" % e["disp"])


def cmd_stats(meta, syms):
    total = sum(len(v) for v in syms.values())
    dup = {k: v for k, v in syms.items() if len(v) > 1}
    pad = sum(1 for v in syms.values() for e in v if e["how"] == "pad")
    print("  build id            %s" % meta.get("build_id", "?"))
    print("  index entries       {:,}".format(total))
    print("  distinct names      {:,}".format(len(syms)))
    print("  ambiguous names     {:,}  (covering {:,} entries)".format(
        len(dup), sum(len(v) for v in dup.values())))
    print("  armable via pad     {:,}".format(pad))
    print("  need displacement   {:,}  (designed, not built)".format(total - pad))
    if dup:
        worst = sorted(dup.items(), key=lambda x: -len(x[1]))[:3]
        print("  worst ambiguity     %s" % ", ".join("%s x%d" % (k, len(v)) for k, v in worst))


def cmd_search(syms, pattern, limit=25):
    hits = sorted(k for k in syms if pattern in k)
    if not hits:
        print("  no name contains %r" % pattern)
        return
    print("  %d name(s) contain %r%s" % (
        len(hits), pattern, "" if len(hits) <= limit else "  (showing %d)" % limit))
    for n in hits[:limit]:
        v, _ = verdict(n, syms[n])
        print("    %-46s %-19s %s" % (n[:46], v,
                                      syms[n][0]["at"] if len(syms[n]) == 1 else ""))


def cmd_explain(syms, name):
    v, why = verdict(name, syms.get(name, []))
    print("  %s" % name)
    print("    verdict : %s" % v)
    print("    because : %s" % why)
    if v == "ARMABLE":
        print("    arm at  : %s" % syms[name][0]["at"])
        print("    command : ls-load.py arm <slot> %s" % name)
        print()
        print("    Armable is NOT the same as reachable. Whether it fires depends on whether")
        print("    this traffic executes it --- `probe %s` answers that." % name)


def cmd_suggest(syms, prefix=None, limit=20):
    groups = collections.defaultdict(list)
    for n, v in syms.items():
        if len(v) != 1 or v[0]["how"] != "pad":
            continue
        # Leading-underscore names split to an empty prefix, which showed as a blank
        # 5,828-entry row. Strip leading underscores first so __dn_comp groups under "dn".
        stem = n.lstrip("_")
        groups[stem.split("_")[0] if "_" in stem else stem[:6] or "?"].append(n)
    if prefix:
        names = sorted(groups.get(prefix, []))
        print("  %d armable, unambiguous name(s) with prefix %r" % (len(names), prefix))
        for n in names[:limit]:
            print("    %-50s %s" % (n[:50], syms[n][0]["at"]))
        if len(names) > limit:
            print("    ... and %d more" % (len(names) - limit))
        return
    print("  armable and unambiguous, by name prefix --- largest groups:")
    for pre, names in sorted(groups.items(), key=lambda x: -len(x[1]))[:18]:
        print("    %-12s %5d   e.g. %s" % (pre, len(names), ", ".join(sorted(names)[:2])))
    print()
    print("  Re-run with a prefix to list it, e.g.:  bnk-explore-hooks.py suggest http")


def cmd_probe(syms, names):
    """THE LIVE ANSWER: arm in MONITOR, wait for traffic, report fires, disarm.

    MONITOR because a probe must not alter traffic --- the host evaluates and applies
    nothing. Slots 10 and 11 are the spare LS_TRAMP expansions, deliberately not the demo
    slots, so probing cannot disturb an armed reset feed mid-demo. Disarms in a finally
    block: leaving live .text patched for a hook nobody is watching is precisely the state
    this mechanism exists to avoid.
    """
    ps = pods()
    if not ps:
        sys.exit("*** no Running pods")
    slots, todo = [10, 11], []
    for n in names:
        v, _ = verdict(n, syms.get(n, []))
        if v != "ARMABLE":
            print("  %-42s SKIP  %s" % (n[:42], v))
        else:
            todo.append(n)
    if not todo:
        print("  nothing armable to probe")
        return
    if len(todo) > len(slots):
        print("  %d armable but only %d probe slots --- taking the first %d"
              % (len(todo), len(slots), len(slots)))
        todo = todo[:len(slots)]

    armed = []
    try:
        for n, slot in zip(todo, slots):
            for p in ps:
                # LOAD WITHOUT A HOOK NAME, deliberately. Passing one makes the loader
                # require the object's ELF section to be fentry/<that name> --- the O14
                # identity check --- so any program would be refused for every target except
                # the one it was compiled for. A reachability probe does not care what the
                # ctx MEANS; it only counts entries. Omitting the name lets the object's own
                # section satisfy the check, and slots 10/11 have no typed ctx builder, so
                # the program is handed the generic five-register form.
                #
                # The program therefore reads fields that are not what it expects. That is
                # sound here and only here: the slot is in MONITOR so no verdict is applied,
                # and `fired` counts entries regardless of what the program concludes.
                sh([KUBECTL, "exec", "-i", p, "-c", "f5-tmm", "--", "python3",
                    "/usr/bin/ls-load.py", "load", str(slot),
                    "/usr/share/ls/rst_watch.bpf.o", "1"])
                r = sh([KUBECTL, "exec", "-i", p, "-c", "f5-tmm", "--", "python3",
                        "/usr/bin/ls-load.py", "arm", str(slot), n])
                out = r.stdout.strip()
                if "ARMED LIVE" in out:
                    note = "armed"
                    armed.append((p, n))
                elif "no pad" in out:
                    # One address, one patch. The overwhelmingly likely cause is that this
                    # function is ALREADY armed --- by the demo, or by a previous probe ---
                    # and the pad now holds a call rather than nops. Saying "no pad" for
                    # that is true and useless.
                    note = "already armed elsewhere (skipping; its own slot is counting)"
                elif "NO PROGRAM" in out:
                    note = "load was refused --- see above"
                else:
                    note = out[:44]
                print("  %-34s slot %-2d %-14s %s" % (n[:34], slot, p[-12:], note))
        if not armed:
            return
        print()
        print("  Armed in MONITOR --- the host applies nothing. Drive traffic, then press Enter.")
        try:
            input()
        except EOFError:
            pass
        print("  === which of these does this traffic actually execute? ===")
        for n, slot in zip(todo, slots):
            tot = 0
            for p in ps:
                r = sh([KUBECTL, "exec", "-i", p, "-c", "f5-tmm", "--", "python3",
                        "/usr/bin/ls-load.py", "status", str(slot)])
                for tok in r.stdout.split():
                    if tok.startswith("fired="):
                        tot += int(tok.split("=")[1])
            print("    %-42s fired=%-7d %s" % (
                n[:42], tot, "REACHED by this traffic" if tot else "armed, never executed"))
    finally:
        for p, n in armed:
            sh([KUBECTL, "exec", "-i", p, "-c", "f5-tmm", "--", "python3",
                "/usr/bin/ls-load.py", "disarm", n])
        if armed:
            print("  (disarmed %d)" % len(armed))


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    p = pod()
    meta, syms = load_index(p)
    print("  pod %s, build %s\n" % (p, meta.get("build_id", "?")[:12]))
    cmd = a[0]
    if cmd == "stats":
        cmd_stats(meta, syms)
    elif cmd == "search" and len(a) > 1:
        cmd_search(syms, a[1])
    elif cmd == "explain" and len(a) > 1:
        cmd_explain(syms, a[1])
    elif cmd == "suggest":
        cmd_suggest(syms, a[1] if len(a) > 1 else None)
    elif cmd == "probe" and len(a) > 1:
        cmd_probe(syms, a[1:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
