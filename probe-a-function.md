# Probing a function you were not prepared for: the commands

Every step is a command you run, with what to look for and what to do when it says no. Nothing
here is scripted around; `env/scripts/bnk-demo-generate.sh` runs the same sequence when you want
it automated, and it echoes each command for the same reason this page exists.

The premise: you have a **stripped** TMM binary in a running pod, the two indexes the build
emitted, `clang`, and PREVAIL. You do not need TMM's source, and you never rebuild TMM.

---

## 0 · Where you are running, and against what

```bash
cd ~/eob-tmm
export KUBECTL=env/scripts/bin/kubectl-datkube    # or plain `kubectl` on the datkube host
POD=$($KUBECTL get pods -l app=f5-tmm --no-headers | awk '$3=="Running"{print $1}' | head -1)
echo "$POD"
```

The two indexes must describe the binary in that pod. Check, do not assume:

```bash
$KUBECTL exec -c f5-tmm "$POD" -- sh -c \
  'awk -F"\t" "/^#build_id/{print FILENAME\": \"\$2}" /usr/share/ls/hook-index.tsv /usr/share/ls/signatures.tsv'
$KUBECTL exec -c f5-tmm "$POD" -- python3 /usr/share/ls/ls_buildid.py "$($KUBECTL exec -c f5-tmm "$POD" -- readlink -f /usr/bin/tmm)"
```

Three identical build ids. If they differ, stop — `ls-load.py` will refuse to arm anyway, which
is correct and tells you nothing about which artifact is stale. Re-run the pipeline
(`bnk-package.sh`, then `bnk-bake-tools.sh`).

You also want the signature index locally, because generation happens where `clang` and PREVAIL
are, not in the pod:

```bash
scp starin@10.145.42.119:~/lstools/signatures.tsv .
head -2 signatures.tsv                            # same build id as above
```

---

## 1 · Find candidates from a QUESTION, not from a name you remember

Ask what you actually want to know, then look for functions whose arguments could answer it.
`signatures.tsv` is name → parameter names, types, and the kind each maps to.

```bash
grep -P '^(flow_|ip4_|ip6_)' signatures.tsv | awk -F'\t' '{printf "%-34s %s args  %s\n", $1, $2, $3}'
```

Read the third column. `scalar` arrives in a register and is free. `string` and `blob` are
pointers and need `bpf_probe_read`. `opaque` and `unknown` mean the generator could not classify
the type and will drop the field.

**What you are looking for is a human-written argument.** A reason code is useful; a
`char *reject_cause` is better, because somebody wrote it as English:

```bash
grep -P '^ip4_reject\t' signatures.tsv
# ip4_reject  3  pkt:blob:struct packet *|send_icmp_error:scalar:enum ?|reject_cause:string:char *
```

---

## 2 · Can it be armed in THIS build?

Different question, different index. `hook-index.tsv` is name → arm address, method, pad offset.

```bash
$KUBECTL exec -c f5-tmm "$POD" -- sh -c \
  'awk -F"\t" -v n=ip4_reject "\$1==n{print \"arm_at=\"\$2\"  method=\"\$3\"  pad_offset=\"\$4}" /usr/share/ls/hook-index.tsv'
```

Or ask for it in sentences, which also counts the entries for you:

```bash
python3 env/scripts/bnk-explore-hooks.py explain ip4_reject
```

Four verdicts, and the three refusals matter as much as the pass:

| verdict | meaning |
|---|---|
| `ARMABLE` | padded, name unique — arm it |
| `AMBIGUOUS` | several entries under one name; arming refuses rather than pick a homonym |
| `NEEDS DISPLACEMENT` | no pad — a separately built component, e.g. OpenSSL. Path not built |
| `NOT ARMABLE` | inlined or folded away by the optimiser |

`pad_offset=4` is armable today. `pad_offset=0` exists (statics, `.isra`/`.constprop` clones) and
`ls_arm` refuses it — it requires `endbr64` and arms at entry+4.

**Armability is a property of the BUILD, not of the function.** `http2_stream_abort` was
`pad_offset=4` on one build and `0` on the next, from identical source, because profile-guided
optimisation changed whether it is an indirect-call target.

---

## 3 · Is it actually REACHED? Measure; do not reason.

The step that gets skipped. Generate, install and arm the candidates, then read the counter —
`fired` is exact whether or not anything else works.

```bash
for FN in flow_reject flow_input_drop flow_reject_dos ip4_reject; do
  python3 substrate/mk_probe.py --index signatures.tsv --function $FN -o /tmp/$FN.bpf.c >/dev/null
  clang -O2 -g -target bpf -I substrate -c /tmp/$FN.bpf.c -o /tmp/$FN.bpf.o
done
```

Arm each in its own slot (0 is the built-in shield; 1–11 are yours):

```bash
S=1
for FN in flow_reject flow_input_drop flow_reject_dos ip4_reject; do
  python3 env/scripts/bnk-deliver-program.py /tmp/$FN.bpf.o $S 1
  $KUBECTL exec -c f5-tmm "$POD" -- python3 /usr/bin/ls-load.py arm $S $FN
  S=$((S+1))
done
```

Drive whatever traffic represents the question, then read the counters:

```bash
$KUBECTL exec client -- sh -c 'for i in 1 2 3 4 5 6; do timeout 1 nc -z 11.11.11.99 9999; done'
for S in 1 2 3 4; do $KUBECTL exec -c f5-tmm "$POD" -- python3 /usr/bin/ls-load.py status $S; done
```

Measured on 2026-08-19: `flow_reject` 8, `flow_input_drop` 7, `flow_reject_dos` 0,
`ip4_reject` 0. **`ip4_reject` is armable and never executes on this path.** No amount of reading
the source would have told you that, and the `reject_cause` string that made it attractive is
unreachable here.

> **Counters are per SLOT and survive a program swap.** Load a second program into slot 5 and it
> inherits the previous one's `fired` and `safe_returns`. Reading `fired=699` as evidence about
> the program you just loaded is wrong, and it has been read that way here before —
> a `safe_returns=246` left by one program was twice cited as a result for the next.
>
> **`gen` is how you tell residue from result.** It increments on every load into that slot, so
> `gen=6` means five programs preceded yours and every counter beside it is cumulative. Either
> use a slot nothing has touched, or take the delta across your own trigger:
>
> ```bash
> B=$($KUBECTL exec -c f5-tmm "$POD" -- python3 /usr/bin/ls-load.py status 5 | grep -oE 'fired=[0-9]+')
> $KUBECTL exec client -- sh -c 'for i in 1 2 3 4 5 6; do timeout 1 nc -z 11.11.11.99 9999; done'
> A=$($KUBECTL exec -c f5-tmm "$POD" -- python3 /usr/bin/ls-load.py status 5 | grep -oE 'fired=[0-9]+')
> echo "before $B  after $A"
> ```

> **Four map slots, for the life of the process.** Each generated probe declares its own output
> map; `LS_MAP_MAX` is 4, the table is keyed by symbol name and shared per process, and `revoke`
> disables a program **without** reclaiming its map. A fifth probe counts correctly and publishes
> nothing. Screening burns registrations, so screen on the counter and keep only the probes whose
> records you intend to read.

---

## 4 · Generate the record and the program

```bash
python3 substrate/mk_probe.py --index signatures.tsv --function flow_reject -o /tmp/probe.bpf.c
```

It prints the signature it read, the fields it kept, and the fields it dropped with the reason.
Read the dropped list — that is where the answer to your question goes missing quietly.

```bash
sed -n '/^struct rec/,/^};/p' /tmp/probe.bpf.c     # the record layout it chose
sed -n '/^__u64/,$p'          /tmp/probe.bpf.c     # the whole program
```

Two things in the emitted code are load-bearing:

- `present` — one bit per captured argument. A `probe_read` that fails leaves the field **zero
  and its bit clear**, so absent is distinguishable from "the value really was zero". Check it
  when you decode.
- the output map's name is a digest, not the function name. TMM records map names in a 32-byte
  table and **refuses** longer ones; a refused map is silent, so a long name gives you an exact
  counter and no records.

Add `--no-probe-read` for a target build without `bpf_probe_read` (helper 4): scalars only,
pointer arguments dropped, and the generated file says so. It refuses outright if that leaves
nothing.

---

## 5 · Compile, then verify

```bash
clang -O2 -g -target bpf -I substrate -c /tmp/probe.bpf.c -o /tmp/probe.bpf.o
SEC=$(llvm-readelf --sections /tmp/probe.bpf.o | grep -o 'fentry/[^ ]*' | head -1); echo "$SEC"
./ebpf-verifier/bin/prevail /tmp/probe.bpf.o "$SEC" \
    --termination --strict --no-division-by-zero --stack-size 256
```

Pass the flags explicitly. PREVAIL's defaults are permissive — `--termination` is *"Default:
ignore"*, `--allow-division-by-zero` is *"Default: allow"*, `--strict` is off — so "verified"
without them means materially less than it sounds.

The section name **is** the hook. Nothing beside the object records what it attaches to, which is
why it cannot be loaded against a different function than it was built for.

---

## 6 · Install it into the running TMM

```bash
python3 env/scripts/bnk-deliver-program.py /tmp/probe.bpf.o 5 1     # slot 5, mode 1 = MONITOR
```

The bytes travel on stdin into the loader socket. Nothing is written to the pod's filesystem, and
the hook name is read from the object's own `fentry/` section rather than retyped. Mode 2 is
ENFORCE; use 1 until you know what the program does.

Every load prints `unverified=yes`. That is honest: there is **no signature verification**, the
loader accepts what it is given, and that is what makes this lab-only.

---

## 7 · Arm it, by name

```bash
$KUBECTL exec -c f5-tmm "$POD" -- python3 /usr/bin/ls-load.py arm 5 flow_reject
```

By name, never by address. The name resolves through the index, gated on the build id, and the
five bytes are read before anything is written — nops proceed, an existing `e8` says already
armed, anything else refuses. Arm on **every** pod or requests will land on one you are not
watching.

Confirm from process memory rather than from the loader. `status` reports `armed=1` whenever the
slot holds a program, which stays true after a successful disarm:

```bash
A=$($KUBECTL exec -c f5-tmm "$POD" -- sh -c \
    'awk -F"\t" -v n=flow_reject "\$1==n{print \$2}" /usr/share/ls/hook-index.tsv')
$KUBECTL exec -i -c f5-tmm "$POD" -- python3 - "$A" <<'PY'
import os, sys
pid = next(d for d in os.listdir("/proc") if d.isdigit()
           and os.path.basename(os.readlink("/proc/%s/exe" % d)).startswith("tmm"))
with open("/proc/%s/mem" % pid, "rb") as m:
    m.seek(int(sys.argv[1], 16)); print(" ".join("%02x" % x for x in m.read(5)))
PY
```

`e8 xx xx xx xx` is armed. `90 90 90 90 90` is not.

---

## 8 · Drain, then trigger, then drain

In that order. The ring persists and ambient traffic produces records with nobody sending
anything, so undrained records read as fresh evidence for whatever you just did.

```bash
$KUBECTL exec -c f5-tmm "$POD" -- sh -c 'timeout 3 /usr/bin/ls_drain --segment /tmp/ls_tp_ring >/dev/null'
$KUBECTL exec client -- sh -c 'for i in 1 2 3 4 5 6; do timeout 1 nc -z 11.11.11.99 9999; done'
$KUBECTL exec -c f5-tmm "$POD" -- python3 /usr/bin/ls-load.py status 5
$KUBECTL exec -c f5-tmm "$POD" -- sh -c 'timeout 4 /usr/bin/ls_drain --segment /tmp/ls_tp_ring' | grep '"slot":5,'
```

`ls_drain` exits 124 on its timeout. That is the timeout, not a failure.

A record from a generated probe looks like this — `hook":"prog"`, `schema":100`:

```json
{"ts_ns":...,"slot":5,"hook":"prog","schema":100,"len":20,
 "data":"01000000504b00004a000000401b447c143f0000"}
```

The host validated the **length** and nothing else, so it prints bytes rather than naming fields
it cannot vouch for. That is the honest gap: you hold the layout, the consumer does not.

---

## 9 · Decode with the layout the generator emitted

```bash
python3 - <<'PY'
import struct
b = bytes.fromhex("01000000504b00004a000000401b447c143f0000")
present, = struct.unpack_from("<I", b, 0)          # struct rec { __u32 present; char pkt[16]; }
print("present = 0b%s" % format(present, "04b"))   # bit i set = arg i captured
pkt = b[4:20]
print("pkt[16] =", " ".join("%02x" % x for x in pkt))
for off in (0, 4, 8, 12):
    print("  +%-2d 0x%08x" % (off, struct.unpack_from("<I", pkt, off)[0]))
PY
```

Check `present` first. A clear bit means `probe_read` refused that pointer and the field is
absent, not zero.

---

## 10 · Disarm, and verify the bytes went back

```bash
$KUBECTL exec -c f5-tmm "$POD" -- python3 /usr/bin/ls-load.py disarm flow_reject
```

`disarm` takes the **name**, not the slot — it resolves the same way `arm` does, so that arming
by name and disarming by a hand-typed address cannot restore nops over something else. Then read
the entry again with the step 7 command: `90 90 90 90 90`, byte-identical to before.

---

## What this procedure cannot do

- **No signature verification.** Every load says `unverified=yes`. Lab only.
- **Four map slots per process**, not reclaimed by `revoke` — see step 3.
- **`pad_offset=0` functions are refused**, and 30,009 functions in this binary have no pad at
  all. Displacement would reach them; it is not built.
- **Fields the generator drops** are gone: beyond five arguments, unclassifiable types, and
  anything past the 96-byte context ceiling PREVAIL enforces.
- **Per-call cost is unmeasured.** `rdtsc` here is preemption-polluted and the node blocks
  hardware counters. `fired` is exact; `cycles` is not a per-call number.
- **The consumer cannot decode a generated record** without being handed the layout.
