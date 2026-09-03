# Symptom index — paste the error, find the answer

**Why this file exists.** The records here are organised by *topic*; a symptom arrives as a *string on a
screen*. Twice on 2026-09-02 the answer to a message I was staring at for an hour was already written
down — `runbook §12g` predicted an entire `F5VirtualServer` dead end symptom-for-symptom, and
`LS_VM_SELFTEST` (which `GROUND_TRUTH` records as having already cost four days once) sat unretrieved
while a CVE demo was called blocked. The knowledge existed; the *lookup* didn't.

So this index is keyed on **the literal text you will have in front of you**, not on the subject it
belongs to. Grep it before investigating anything:

```sh
env/scripts/ask 'Waiting for one or more dependent CRs'
```

**Add a row every time a symptom costs more than ten minutes.** A row is cheap; re-deriving is not.

---

## Cluster / listeners

| symptom (literal) | what it actually means | where |
|---|---|---|
| `Waiting for one or more dependent CRs to be applied` on an `F5VirtualServer` | **It will never program.** `F5VirtualServer` is a **CNF**-profile shape; BNK uses **Gateway API**. It resolves dependencies as kinds `F5BigCnePool`/`F5BigNetVlan`, **neither installed** under `bnk-core`, and confusingly the `Pool`/`F5SPKVlan` instances that *do* exist share the same names, so everything looks healthy. Do not write better CRs. | `env/bnk-dev-runbook.md` §12g · `cve-mitigation-milestone.md` §4C |
| `No IPAM Range resource found on start of controller` | **Not a missing range and not a stale cache.** An `IPAMRange` exists (`default/eob-range`); restarting the controller does not change the message. `F5VirtualServer` has **no `ipamLabel` field** and the LoadBalancer Service it creates carries **no annotations**, so nothing ever requests an address. | `cve-mitigation-milestone.md` §4C |
| A `LoadBalancer` Service stuck `<pending>` forever (`f5-tmm-tcp-service`) | Same story as the two rows above — one story, not three. The runbook's words: *"every symptom then points at ports and addresses and none of the fixes hold."* | `env/bnk-dev-runbook.md` §12g |
| `alert handshake failure` when offering Brainpool (or any non-default curve) | Editing `dhGroups` on `sys-default-clientssl` **or** `ls-c3d` is a **no-op** for the Gateway listener — it uses an **auto-generated** profile (`spk-app-1-tls-gateway-…-clientssl-https`). Proved by restricting the profile to `p256` alone and watching x25519 still work. | `cve-mitigation-milestone.md` §4B |
| Gateway `tls.options` set and silently ignored | The CNE controller reconciles the Gateway and reports `Programmed=True` while honouring **none** of `k8s.f5net.com/clientssl-settings`, `k8s.f5net.com/clientssl`, `gateway.k8s.f5.com/clientssl-settings`, `f5.com/clientssl-settings`. There is no discoverable knob for the generated client-SSL profile, and the controller is distroless so its binary cannot be searched for the real key. | `cve-mitigation-milestone.md` §4C |
| Reaching for `bnk-external` to get a TLS listener | It has **no TLS listeners** — HTTP, TCP (`L4Route`) and gRPC only. The profile that ships `F5VirtualServer` + a *named* `clientssl` is **`access-bnk`**. And `datkube install --components-only` means a profile change is **not** a cluster rebuild — but it may replace `bnk-core`'s components, which include `deploy/f5-tmm` and the toolbox. | `cve-mitigation-milestone.md` §4C |
| About to run `datkube create-cluster` / `recreate-cluster` / `install` | **STOP — the default `-n KIND_CLUSTER_NAME` is `datkube`, which is the name of the RUNNING cluster.** An unqualified `create-cluster` destroys it, taking the armed shield, the deployed vulnerable image and the toolbox with it. Always pass `-n <other-name>`. Note also that creating a cluster switches the kubectl context (`kind-datkube` -> `kind-<new>`), so every command aimed at the original must then be explicit with `--context kind-datkube`. | `datkube --help` |
| `datkube uninstall crd` (under any `cnf-*`/`ltm`/`xc-core` profile) | **Never run it on a shared cluster.** It executes `kubectl delete crd --force $(kubectl get crd \| awk '/f5/{print $1}')` — deleting **every f5 CRD**, i.e. all BNK config: gateways, pools, listeners, profiles. It is the uninstall half of the component that ships the CNF/LTM CRDs. | `profiles/*/profile.yaml` |
| A probe fires on the HTTP VIP but not "TLS" | There are three gateways: `gateway` **11.11.11.99** (HTTP), `tls-gateway` **11.11.11.97** (HTTPS/Terminate, cert `ls-tls`), `dns-gateway` .98. Probing `.99:443` gets connection refused — right cluster, wrong address. | `cve-mitigation-milestone.md` §4B |
| A `grep` over cluster resources returns **nothing**, and you conclude the thing does not exist | **Suspect the pattern before the cluster.** `kubectl get crd \| grep -iE "security\|psm\|waf\|firewall"` returns zero hits here — the resources are named **`SecPolicy`** and **`F5BigFwPolicy`**. `sec` is not `security`; `fw` is not `firewall`. A wrong pattern and a true negative look identical and raise no error. **Enumerate unfiltered, then narrow**, and grep on stems. | `CONTESTED-PREMISES.md` 13 |
| `error: the server doesn't have a resource type "bnksecpolicies"` | The **published CRD reference and the cluster use different names.** The docs say `BNKSecPolicy`, `F5BigCneIrule`, `F5SPKVLAN`; the cluster has `SecPolicy` (`secpolicies.gateway.k8s.f5.com`), `f5-big-cne-irules.k8s.f5net.com`, `F5SPKVlan`. Always resolve a kind against `kubectl get crd` before using it. | `SOURCES.md` (BNK CRD reference) |
| `kubectl … -n bnk-core` or `-l app=f5-tmm` returns empty, and nothing looks wrong | **Wrong namespace and wrong label — both guessed.** TMM runs as `f5-tmm-<hash>` in namespace **`default`** on this cluster, alongside `client`/`server` (the traffic drivers) and `tmmtrace-toolbox`. `bnk-core` does not exist here. An empty result from a guessed selector reads exactly like a healthy absence. | this file |

## Loading / arming a program

| symptom (literal) | what it actually means | where |
|---|---|---|
| `ERR load refused (identity mismatch, malformed ELF, or uBPF rejected it)` | Three distinct causes wearing one message: **(1)** the `.sig` was not staged next to the `.bpf.o` in the pod; **(2)** the object carries **zero CO-RE relocations** (`rc=-3`) — see next row; **(3)** the ELF's section does not match the hook it was submitted under (finding O14). | `GROUND_TRUTH.md` · `substrate/ls_vm_load.c` |
| `rc=-3` / zero-relocation refusal | The relocator refuses an object with no relocations. Add a harmless **canary field read**; `tmmtrace` does this automatically whenever the program emitted no reads (an unpredicated `count()`, or a predicate on a scalar arg). | `substrate/tmmtrace.py` (`codegen`) |
| `rc=-5` / `LS_RELO_ENOFIELD` | `btf_find_struct` returns the **first** same-named BTF type, which can be a **forward declaration** with no members (`connflow`). Fix: prefer a defined struct (non-zero size/vlen). Note `gen_type_catalog.py` already does exactly this — the relocator does not. | `substrate/ls_core_relo.c` · memory `dtls-shield-demo-state` |
| `could not resolve path 'cf.mss' … connflow has no scalar 'mss'` | Multi-hop resolution worked (it *found* `connflow`); the catalog omits **bitfield** members. Different limitation from hops. | `substrate/gen_type_catalog.py` |
| A predicate on a flag field (`is_trailer`, `state`, `mode`…) that reads plausibly but never matches — or matches everything | **It is a BITFIELD and the read was silently wrong.** Until 2026-09-02 the catalog emitted bitfields as plain scalars (`http_parse_info.is_trailer` was advertised as `u32` — it is **1 bit at bit 0** of a word holding ~17 flags), so a read returned the whole unit. `ls_core_relo.c` does not catch it: it refuses a sub-byte offset (`bit_off % 8`), so bit-1+ fields fail loudly but a field at **bit 0 succeeds silently**. 6,960 catalog entries were affected. Now bitfields are excluded from the scalar map and described under `__bitfields__`, and the DSL refuses them by name. **Correct reads still need clang's bitfield relocation kinds in the relocator.** | `substrate/gen_type_catalog.py` · `substrate/ls_core_relo.c:203` |
| `<struct> has no pointer field '<name>'` on a path you know exists | The member is an **EMBEDDED struct, not a pointer**. Multi-hop only walks pointer edges, so e.g. `args.http_data.ci.…` dies at `ci` even though `ci` is right there — and `http_data`'s whole scalar surface is 2 fields because the rest is embedded. The relocator already accumulates offsets across an accessor chain, so this needs a catalog `__embedded__` edge set + nested type declarations in the codegen, **not** relocator work. | `substrate/tmmtrace.py` (`resolve_path`) |
| `error: redefinition of 'xbuf'` (clang, generated program) | Two fields of one struct were referenced. Fixed 2026-09-02 by accumulating fields per struct and emitting one declaration each — should not recur; if it does, `_read`/`reg` regressed. | `substrate/tmmtrace.py` |
| `bench` rejects a program that loads and arms fine | `bench` does **not** run the CO-RE relocator, so it refuses any object carrying relocations — i.e. every real `tmmtrace` program. It also caps iterations at **20000**. Use the budget pass for a bound, not bench. | `env/toolbox/tmmtrace` (`cost`) |

## Measuring — where a clean-looking number is wrong

| symptom (literal) | what it actually means | where |
|---|---|---|
| `fired = 0` / `matched = 0` on a probe that "should" fire | **First prove the probe armed.** Never suppress `arm` output and then read a counter — `fired=0` reads identically whether the hook never fired or nothing was ever loaded. Cost an hour on 2026-09-02. | `GROUND_TRUTH.md` |
| `status` says **`armed=1`** but `fired` stays 0 forever | **`armed=1` means a program OCCUPIES THE SLOT, not that the function entry is patched.** `load` and `arm` are two operations (`load <slot> <file> [mode]`, then `arm <slot> <name>`); loading alone leaves the pad untouched and every counter at 0. Cost several rounds on 2026-09-02, *after* the row above already said "first prove the probe armed" — I read `armed=1` as that proof. The real proof is `arm`'s own output: `OK ARMED LIVE entry=0x… slot=N kind=fentry`. Always pass a NAME, never a raw address: a name is resolved through the index and checked against the running build id. | `env/scripts/ls-load.py` (usage block) |
| A slot shows plausible non-zero counters that never change | Its program is loaded but its hook is **disarmed** (or was disarmed since). Counters are cumulative and persist, so a stale slot looks alive. Diff two reads across real traffic before believing any counter. Found 2026-09-02: slot 2 sat at `fired=48` across 24 requests. | `env/scripts/ls-load.py` |
| Pad/inlining numbers that look far too good (e.g. "99% hookable, zero partials") | You measured **`obj_x86_64.debug`**. It has **no pads at all** (`-fpatchable-function-entry` rides `CFLAGS_OPTIMIZE`) and inlines far less than `-O2`. Measure **`obj_x86_64.no_pgo/tmm.no_pgo`**. Same trap `mk_hook_map.py` documents for pads. | `GROUND_TRUTH.md` · `substrate/mk_hook_map.py` |
| A counter that "does not aggregate" / does not match the last batch size | `status` is **cumulative since arm** and never self-zeroes. Use `tmmtrace reset <slot>` between batches. | `env/toolbox/tmmtrace` |
| A hook armed, traffic driven, and the count exceeds what you sent | Per-slot counters accumulate across reloads; `gen` distinguishes loads. Baseline after arm and read the delta. | `env/toolbox/tmmtrace` |
| A shield's counter climbs but some call sites are clearly unprotected | The hook is **partially inlined** — pad exists, inlined copies run unshielded. `tmmtrace list` now flags `[PARTIAL: N inlined site(s)]`; four `http_process_*` functions are real cases. | `GROUND_TRUTH.md` · `engine-hard-problems.md` §3.1 |
| A measurement described as being taken on **"ordinary" / "plain" / "normal" traffic** | **Enumerate the cluster's config before trusting the word.** Two `F5BigCneIrule` resources of mine fired on every handshake and every HTTP response for **seven days** while the cluster was repeatedly described as reverted and clean — one injecting a 70 KB `SSL::cert_constraint` per `CLIENTSSL_HANDSHAKE`. Deleting an experiment's *artifacts* is not reverting its *configuration*. Note the asymmetry: a differential (A/B, same confound both sides) survives this; an absolute claim about normal traffic does not. | `CONTESTED-PREMISES.md` 13 |

## Build / package / deploy

| symptom (literal) | what it actually means | where |
|---|---|---|
| A build "succeeds" but the change is absent from the running binary | `make tmm-gdb` alone ships **old code**: the packaging chain is version-stamped and the substrate is untracked, so `VERSION` never changes. Run `bnk-package.sh`, which clears the stale chain and then **verifies against the sources**. | `env/scripts/bnk-package.sh` |
| Link fails on a new global symbol | TMM's globals whitelist is exact in **both** directions. Add the symbol to **both** `src/compile/default_whitelist_x86_64` and `debug_whitelist_x86_64`; predict the name with `nm` on the object. | `substrate/TMM-TREE-DELTA.md` §2 |
| `bnk-sync-substrate.sh` refuses: *"could not read the only-in-tree count"* | It is written to run **from the Mac** driving the build box over SSH; running it *on* the build box breaks its own check-parse. For a content-only change, verify the file lists match, copy the files, and clear `obj_x86_64.*/ls_*.o` by hand. | `env/scripts/bnk-sync-substrate.sh` |
| TMM crashed and `kubectl logs --previous` is empty | When TMM dies the **pod is replaced**, not restarted, so there is no previous container to read. Start `kubectl logs -f <pod> > file &` **before** triggering the crash. | `GROUND_TRUTH.md` |
| TMM segfaults on an arm that should be harmless | `LS_VM_SELFTEST` is still set. At level 2 it performs a real NULL dereference whenever the armed program returns `FALLTHROUGH` — so *any* later probe can kill TMM. Unset it after the crash demo. | `GROUND_TRUTH.md` |

## Reaching for the wrong tool

| symptom (literal) | what it actually means | where |
|---|---|---|
| "We cannot demonstrate the CVE because the path is not reachable" | **Stop.** `LS_VM_SELFTEST` feeds the CVE condition directly to the armed program and performs the real dereference — crash-to-no-crash with one variable. It is the same method the dev teams use (`src/test/standalone`) when a path is hard to reach through config. This exact omission has now cost time **twice**. | `GROUND_TRUTH.md` · `substrate/ls_vm.c` (`ls_vm_selftest`) |
| A CVE's fix commit cannot be found by CVE id | Commit messages carry **BZ ids and `[EMBARGO]`**, not CVE numbers. `git log --all -i --grep=EMBARGO` enumerates the security fixes; bridge CVE→BZ via Bugzilla REST (`SOURCES.md`). | `cve-mitigation-milestone.md` §7 |
| "The CVE's precondition is not settable — it is not in the CRD's field list" | **The CRD field list is not the whole configuration surface.** `F5BigCneIrule` takes a **free-form TCL string** (`spec.iRule`) that runs inside TMM at protocol events, vendor-sanctioned, and reaches internal calls no CRD field exposes — measured: `SSL::cert_constraint` with a 70,000-byte value, logged before *and* after, 0 restarts. Check the iRule command surface before writing a precondition off. **But do not overclaim it either:** no iRule command sets `enforce.ltm_http_rfc`, so this is a lead to enumerate, not a solved reachability problem. | `GROUND_TRUTH.md` · `CONTESTED-PREMISES.md` 13 |
