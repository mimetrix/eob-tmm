# Loader client — driving a live TMM

The other half of the load path. `ls_vm_load.c` runs a loader thread inside TMM; everything here is
what talks to it.

**Why this directory exists.** Every live result recorded in this repo was produced by scripts that
lived in a scratch directory and were never committed. The in-TMM half was reproducible and the
client half was not, which meant none of those results could be re-run by anyone else. That was a
real reproducibility failure, and this closes it.

## What this is not

**Not the operator front-end.** Scope item 11 is *not written*; `shieldctl` in the walkthrough is
illustrative naming for a `tmsh` subcommand and iControl endpoint that do not exist.

**Authenticated, but still lab-only.** Signature verification (item 4) is built: the loader
refuses any program whose Ed25519 signature over the binding does not check out against the key
baked into TMM. What keeps this away from a production box is no longer the missing signature ---
it is that the socket is env-gated on `LS_LOAD_SOCKET` with no authentication of the *peer*, so
anything that can reach the socket can ask, and `LS_SIG_ENFORCE` can turn the check off.

**Hand-encoded wire layout.** `ls_client.py` transcribes offsets from `../shield_abi.h` rather than
deriving them. Change `struct shield_msg` and this breaks *silently*. `verify_layout()` pins the
arithmetic so the numbers can be checked against the struct in one pass — but a generated client is
the right long-term answer, and is part of item 11.

## Files

| file | what it does |
|---|---|
| `ls_client.py` | the wire protocol, as a library and a CLI (`status` · `load` · `arm` · `disarm`) |
| `check_load_distinct.py` | **the evidence artifact.** Proves *distinct* bytecode is loaded and discriminated |
| `test_load2.py` | pushes one real program in; the basic "does the load path work" check |
| `load_burst.py` | repeated loads while traffic flows, timing each |
| `hot_hook_cost.py` | arms a hot function with a program that always falls through, to price the hook |
| `hot_delta.py` | the same, by delta between two bursts, so cold-start is excluded |
| `arm_client.py` | one arm/disarm against one instance |
| `arm_all.py` | arms one function across **every** TMM instance in the pod |

> **The production image has no Python.** These clients only ever ran against debug builds — and a
> debug build is precisely one that *cannot* be armed, because the debug variant overrides
> `CFLAGS_OPTIMIZE` and so carries no entry pads on TMM-core functions. So the whole directory
> worked only where the mechanism does not, which went unnoticed until a production image was
> finally shipped.
>
> Against a production build, drive the socket with **`ncat -U`** and a message built off-box —
> no client in the container at all:
>
> ```sh
> python3 -c 'import struct,sys; m=struct.pack("<IIBxxxI",3,0,2,0)+b"\0"*32+b"\0"*64+b"\0"*16+b"\0"*64; sys.stdout.buffer.write(m)' > /tmp/status.bin
> kubectl exec -i <pod> -c f5-tmm -- ncat -U -w5 /tmp/ls_load.sock.<n> < /tmp/status.bin
> ```
>
> Verified working: `OK armed=1 mode=2 fired=0 …`. The 192-byte layout is in `ls_client.py`.

## Running

The loader must be on — TMM started with `LS_LOAD_SOCKET` set. It names one socket per instance,
so there is normally more than one.

```sh
python3 ls_client.py status
python3 ls_client.py load /tmp/shield.elf http_psm_profile_name_lookup
python3 ls_client.py arm 0xcd4700
python3 ls_client.py disarm 0xcd4700
```

**The address is supplied by hand and moves with every rebuild.** The hook-map generator (item 5)
is unbuilt, which is what would resolve a name to an address. Read the address from the matching
`tmm-debuginfo` package, **not** from the build tree — packaging re-links the binary, so the build
IDs differ.

## Reading `check_load_distinct.py` — step 2 is the test

An earlier check loaded the shield already compiled into the binary, which proved the *path* worked
but not that different bytes could arrive: what went in matched what was already there.

This one loads two trivially distinguishable programs and uses the loader's own identity check as
the discriminator. `ls_vm_reload` builds the section from the declared hook and refuses unless the
program's own section matches (finding O14: PREVAIL proves a **section**, uBPF runs a **symbol**).

Step 2 — `demo_pass` submitted under `hook=demo_block` — must be **REFUSED**. If the loader were
ignoring the submitted bytes and reusing what was resident, step 2 would succeed. That refusal, not
the two successes around it, is the evidence.

It expects `/tmp/demo_block.elf`, `/tmp/demo_pass.elf` and `/tmp/shield.elf`, built from
[`../shields/`](../shields/).

## Known-bad ops

`0x1001` (BENCH) and `0x1002` (SAMPLES) still run on the **loader** thread rather than going
through the prepare handoff, so they hit TMM's allocator on a foreign thread and **wedge the
loader**. Do not call them. This is why the per-call hook cost is still unmeasured — see
`../../load-path-scope.md` §7.
