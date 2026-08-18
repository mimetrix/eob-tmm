# The entry-padding measurement — the method behind the numbers

These four files produced the figures that a dozen documents in this repository cite:
`-fpatchable-function-entry=5,0` reaching **48.9%** of the shipped binary's functions,
**+0.476%** `.text` growth, and alignment slack absorbing **21%** of the nominal pad width.

**They existed only on the build box until 2026-08-18.** The numbers were quoted
everywhere and the method that produced them was on one disposable VM — the same exposure
that lost the uBPF helper registrations, `harness.c`, and eight whitelist symbols earlier.
They are recovered here as a record, not as tooling anybody should run again unmodified:
every path in them is a hard-coded `/tmp` location from that session.

| file | what it did |
|---|---|
| `nops.py` | Counted 5-byte `nop` runs in `.text` for a baseline and a flagged build. Distinguishes `90 90 90 90 90` runs from longer runs, and counts the multi-byte `nopl 0x0(%rax,%rax,1)` form separately — because the compiler emits both and only one of them is our pad |
| `entry.py` | Read the bytes at each function entry, resolving virtual addresses through the section headers, to classify what the entry actually looks like |
| `coverage.py` | The coverage figure: sampled function entries against the debuginfo symbol table and counted how many carry a pad |
| `Makefile.overrides.patchable5` | The build override used for the flagged half of the comparison |

## Why the override in here says `:=` and the production one does not

```make
# from Makefile.overrides.patchable5
CFLAGS_OPTIMIZE := -O2 -fpatchable-function-entry=5,0
```

For a **controlled comparison** that is correct: the experiment wants both halves compiled
at a known, identical optimisation level, so replacing the tree's selection is the point.

That line was then carried into the production `Makefile.overrides`, where the semantics
are wrong. `Makefile.inc:96-100` selects `-Os` when `VADC_TRIAL=yes` and `-O2` otherwise, so
a `:=` silently forces a VADC trial build from `-Os` to `-O2`. It went unnoticed for months
because the default build selects `-O2` anyway, making the common case byte-identical.

Corrected 2026-08-18 to `CFLAGS_OPTIMIZE += -fpatchable-function-entry=5,0`. See
`substrate/TMM-TREE-DELTA.md` §4.

**The general lesson is worth more than the specific bug:** a line that is correct in an
experiment can be wrong in production for reasons the experiment was designed to exclude.
Copying it forward carries the exclusion with it, silently.

## The scoping caveat these numbers require

48.9% is **whole-binary** and correct as such. It is not "coverage" of the shield's scope:
TMM is assembled from roughly two dozen independently built components, and the flag reaches
none of them. Inside the TMM core the figure is **82–97%**. Quoting the whole-binary number
as coverage averages in code that was never in scope — see `mechanism-tradeoff.md`.
