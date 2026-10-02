# tmmtrace scripts: keyed state, time and records across hooks

**2026-10-02 — registered before implementation.** Contract and falsifiers for
extending `tmmtrace` from one stateless expression to a short script of probes
that share keyed state. Reference program: the hand-written
[`aigw_timing.bpf.c`](surfaces/aigw_timing.bpf.c) (P24), which the generated
program must match in behavior.

## Why

A one-line probe can count or histogram a value at one function. Latency needs
two points: a start recorded under a key, and an end that looks up the key and
emits the difference. Today that needs hand-written C. The paper's §7.1 goal is
that `tmmtrace` becomes the main authoring tool, so the language needs state
across hooks.

## Language

A **script** is one or more probes separated by `;` or newlines. All probes in a
script compile into **one ELF** with one entry section each and **shared maps**.
It is signed once as an owned program (`@program-v1`) and loaded with
`program-load`. A single probe without `@` state keeps today's legacy output, so
existing expressions generate byte-identical C.

```text
<script> := <probe> { (';' | newline) <probe> }
<probe>  := ('fentry'|'fexit') '/' <hook> [ '/' <pred> '/' ] '{' <stmt> { ';' <stmt> } '}'
<stmt>   := '@' <map> '[' <key> ']' '=' <expr>          # store
          | 'delete' '(' '@' <map> '[' <key> ']' ')'    # remove
          | 'emit' '(' <expr> { ',' <expr> } ')'        # one record, up to 6 values
          | <legacy action>                             # count() | hist(v) | v | shield(v)
<key>    := <value>
<expr>   := <term> [ '-' <term> ]
<term>   := 'nsecs' | <value> | '@' <map> '[' <key> ']' | <int>
<value>  := as today: args.f | argN | argN.f | args.a.b.c ...
```

New elements:

- `nsecs`: the monotonic clock (helper 5, `CLOCK_MONOTONIC`, nanoseconds).
- `@m[k]`: a per-script hash map, key 8 bytes, value 8 bytes, 128 entries. A read
  of a missing key yields 0 and sets a `MISSING` flag on that probe's record.
- `emit(...)`: writes one fixed record to the ring: magic, script ID, probe
  index, a sequence number, the timestamp, a flags word, then up to six u64
  values in the order written. The consumer names the columns from the script.
- `args.f` on a **void pointer** argument is refused today. Add an explicit
  cast form for opaque arguments: `(struct aigw_host_ctx *)arg0->scb`. The cast
  struct must exist in the type catalog.

## The reference script

```text
fentry/aigw_rbac_admit         { @t0[arg0 + 64] = nsecs; emit(arg0 + 64, 0) }
fentry/aigw_host_session_event /args.ev == 4/
                               { emit(args.scb, nsecs - @t0[args.scb]) }
fentry/aigw_host_reply_done    { emit(args.scb, nsecs - @t0[args.scb], args.flags) }
```

`arg0 + 64` is the inline `hudnode.ctx` (the aigw_scb). The language allows
`+ <int>` on a value only for this address form; general arithmetic stays out.

## Falsifiers

Reject the implementation if any of these occur:

1. An existing single expression generates different C than today.
2. A script fails pinned clang-18 or PREVAIL (256-byte stack) on any entry.
3. Entries of one script do not share a map, or two scripts share a map.
4. A missing key yields anything but 0 with the `MISSING` flag set.
5. `emit` with more than six values, a map used before it is defined anywhere
   in the script, `&&` and `||` mixed, or a cast to an unknown struct is
   accepted instead of refused with a message.
6. The reference script, run natively against the same authored request as
   `check_aigw_timing.c`, gives a different admit-to-done duration than the
   hand-written program.
7. Live: the generated program and the hand-written one, run on the same
   requests, disagree on a stage by more than 1 ms.

## Out of scope

Aggregation inside the program (`@h = hist(...)` in a map), string values,
loops, `printf`, user-space map reads. The consumer computes histograms from
the emitted records, as `tmmtrace hist` does today.
