# What this mechanism can and cannot mitigate

The honest boundary, with the measurement behind each line. Written 2026-08-25 after screening the
full in-TMM finding population and testing three subsystems on a live cluster.

**The one-sentence answer.** It can impose a **missing input check** at the **entry** of a function
that **live traffic actually reaches**, when the checked value is **derivable from that function's
arguments** — and it cannot do anything else.

Every limit below is one of those four words failing.

---

## 1. Terms, because all four get used loosely

| term | means here | why it matters |
|---|---|---|
| **CVE** | a tracked, published vulnerability id | on this product they are almost entirely in *dependencies*, not in TMM |
| **finding** | an F5-internal, triaged security defect in TMM's own source, with a hash like `BIGIP-tmm-B22F115D` | this is the population a shield can act on |
| **mitigate** | the program's verdict changes what the process does — the vulnerable code does not execute | a claim about behaviour |
| **observe** | the program reports; the process is unaffected | a claim about telemetry. Monitor mode is this, and it is not mitigation |

Saying "CVE mitigation" on BNK is a **mislabel**, not a simplification. The accurate framing is
**pre-patch mitigation of known-exploitable data-plane defects**.

---

## 2. What it CAN do — three conditions, all required

**(a) The defect is a missing check on a value the function was handed.**
The fix must be expressible as a predicate over the arguments. `if (len > UINT16_MAX) goto out;` is
the canonical shape: one bound, one early return.

**(b) The function is reachable by traffic the platform can actually be configured to serve.**
Not "TMM has the code" — TMM has code for QUIC, DNS, SIP, IPFIX and APM. Reachable means the
*control plane* can open a listener that drives it.

**(c) The safe disposition is an early return.** The host returns a value on the program's behalf.
If the correct behaviour is anything else — free a buffer, set an error, continue with a clamped
value — an entry return does not reproduce it.

### Proven capabilities, on a live TMM

| capability | evidence |
|---|---|
| Load a signature-verified program into a running process over a socket | `OK loaded slot=7 mode=2 signature=verified` |
| Arm at a real function entry, no rebuild, no restart | `OK ARMED LIVE entry=0xcd1004 slot=7 (no restart)` |
| Fire exactly once per request on the product's traffic path | 40 requests → `fired +40` |
| Report decisions TMM exposes nowhere | reset causes with file, line and cause from live flows |
| Disarm and restore the original bytes | `OK DISARMED LIVE` |
| Flip the outcome with one variable | enforce → `SAFE_RETURN`, survived; monitor → `FALLTHROUGH`, fatal dereference |
| Arm functions with no `endbr64` (`pad_offset=0`) | tested on `quic_process_conn_close 0xe56d80`, armed and disarmed clean |
| Attach an iRule to a live Gateway and have it run | `X-LS-Irule: fired` via `NetPolicy` → `F5BigCneIrule` |

---

## 3. What it CANNOT do

### 3.1 Defect shapes that are not a missing input check

Measured against the 32-finding population; each of these was a candidate until the diff was read.

| shape | example | why not |
|---|---|---|
| **Under-allocation** | `A3009782`: `umalloc(cert_len*2)` → `*2 + 1` | the bug is the allocation, not an unchecked input. Every call is affected, so a predicate could only block them all |
| **Use-after-free / ordering** | `50189B90`: save `pcb` fields before `http1x_free` | an ordering bug *inside* the function. No entry check reaches it |
| **In-loop / pointer-walk validation** | `1570F506`: bounds checks against `end` inside a parse loop | an entry predicate runs once, before the loop exists |
| **Clamp rather than reject** | `DF46CA3F`: clamp `field->val.len` to remaining space | the fix *modifies* a value and continues; a shield can only refuse |
| **Timing side channels** | `CVE-2022-4304`, OpenSSL RSA timing | no predicate over inputs fixes a timing oracle |
| **Anything outside TMM's address space** | dependency CVEs in sidecars, base OS packages | the substrate arms entries in TMM's own `.text`. A different container is a different address space — no hooking mechanism reaches it |

### 3.2 Values the hook cannot see

Our hook is at the **patched function entry**, so a program sees only the arguments as the function
received them. **A check on a value the function computes is unreachable from entry.**

Screened across all 32 findings (`substrate/screen_findings.py`):

```
ENTRY=0   PARTIAL=7   REVIEW=1   INSIDE=15   NOT-A-GUARD=9
```

**Zero** guards read only the arguments. `B22F115D` looked like the best candidate found — one scalar
bound on the core packet path — until the source showed the packet is *received inside the function*:

```c
pkt = tmm_cmp_pkt_rcv(tmm_cmp_comm, sender);        /* obtained here */
packet_data_pullup(pkt, xcur, sizeof(...), &pkthdr);
if (pkthdr->ifc_name_len > IFC_NAME_SIZE) { ... }   /* the check */
```

Dereferencing a pointer *argument* is fine — the host builder chases pointers before the program
runs. Reading something the function created is not.

### 3.3 Context size

PREVAIL admits at most **96 bytes** of entry context. The TLS/ALPN shield needed **154** and was
refused at `154: Upper bound must be at most 96` — **FALSIFIED**, and still is. A candidate whose
predicate needs more state than 96 bytes is out regardless of everything else.

### 3.4 Reachability is set by the control plane, not by TMM

TMM contains the code for far more than BNK can be told to serve. Measured on the cluster:

| subsystem | TMM code | control plane | result |
|---|---|---|---|
| HTTP/1.x, HTTP/2, gRPC, TLS | present | `HTTPRoute`, `GRPCRoute`, `TLSRoute` — the declared route kinds | **reachable** |
| QUIC / HTTP-3 | present, functions armable | no CRD, no `http3` field, **0** controller log mentions, no UDP service | unreachable |
| DNS | present, `dns_pullup` armable | UDP listener programs and traffic flows **10/10** — but the parser is never entered, and no CRD attaches a DNS profile or cache to a listener | **listener reachable, parser not** |
| PSM security logging (the NULL-deref) | present | condition is guarded one frame up in the same function; no configuration can produce it | unreachable *by construction* |

The DNS row is the sharpest lesson: **traffic arriving is not the same as the vulnerable code
running.** An L4 forward relays packets without parsing them.

### 3.5 Dispositions we cannot yet choose safely

There is no safe-return policy table (development scope item 7). Today the returned value is chosen
by hand per hook. `B22F115D` shows why that matters: its correct disposition is `packet_free(pkt)`
then bail, so a bare early return would prevent the overflow **and leak the buffer**. Whether that
trade is acceptable is a judgement no artifact in this repo currently records.

---

## 4. The CVE question, specifically

Enumerated from Bugzilla (paginated; an earlier count of 39 came from reading a truncated
800-result set as a total):

- **3,068** distinct CVE-ish bugs for the product.
- Only **5 of 3,068** name a source file at all. The rest name a **package** and a **container**.
- Top packages: Go `stdlib` 565, `libpython3.12` 124, `golang.org/x/crypto` 99, `libwireshark` 73,
  `libc` 66. Even the data-plane-sounding components are container dependencies: all 46 `AFM` CVEs
  are in `f5-l4p-engine` — Go stdlib, libprotobuf, grpc.
- Plausibly inside TMM's address space: **about two**, one being an OpenSSL RSA timing oracle.
- **Neither is a shape a shield addresses.**

And the objection that settles it is not technical: **a shield does not change the package version,
so the scanner still reports the CVE.** Dependency-CVE pain is audit pain; the fix is an upgrade,
which is cheaper and permanent. Shielding a dependency only wins when no upgrade exists yet.

**So: no CVE in TMM can be demonstrated as mitigated, and that is a property of the population
rather than of this mechanism.**

---

## 5. What would change each limit

| limit | what lifts it | size |
|---|---|---|
| entry-only placement (§3.2) | **displacement** — placement at points other than function entry. Opens the 15 `INSIDE` findings, including the reachable `ssl.c` group | the deciding piece of engineering |
| 96-byte context (§3.3) | a verifier that admits more entry context, or shrinking each candidate's context | per-candidate, or upstream |
| reachability (§3.4) | a platform whose configuration surface reaches DNS, SIP, APM, IPFIX — i.e. **classic BIG-IP**, not BNK | platform choice, not a code change |
| dispositions (§3.5) | build the safe-return policy table | scope item 7, bounded |
| the CVE population (§4) | nothing we can do. It is where the CVEs are | — |

---

## 6. The nearest demonstrable claim today

`D5FCBB04` — `ssl_cert_extension_set`, `if (len > UINT16_MAX) goto out;`

Every link now has a confirmed mechanism: the guard is a scalar bound recomputable from the
arguments `oid_len` and `oid_value_len`; the function is armable (`0x1025604 pad 4`, in the shipped
index); its caller is the iRule dispatcher, and **iRules demonstrably attach to a live Gateway and
run** (`X-LS-Irule: fired`); the call site's guard needs `enableC3d` or `enableForwardProxy`, both
of which exist as clientssl settings fields.

**Untested end to end.** Open: a TLS listener (we serve HTTP today), whether BNK's iRule subset
exposes `SSL_TCL_METHOD_SET_CERT_EXTENSION`, and whether >64 KB of argument can be passed from TCL
to trip the bound.

And note what it would prove. The fix is **present** in this build, so the demonstration is *the
shield imposing the same check the fix imposes*, at a real hook, on live traffic — without
reverting anything or reintroducing a defect. That is a stronger claim than a staged crash, and it
is the honest one: **pre-patch mitigation of a tracked data-plane defect**, not CVE mitigation.
