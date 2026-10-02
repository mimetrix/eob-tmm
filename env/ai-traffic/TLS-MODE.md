# Client TLS mode for each activity record

**2026-10-01 — MEASURED in isolated live TMM, one worker, HTTP/1.** Each combined
activity record now states how TMM handled TLS on the client connection.
16 live exchanges through plain and client-SSL virtual servers give the expected
class. Protocol and cipher ID match the client's own record in all 15 TLS
exchanges. Identity stays `unknown`. [Result](#measured-result),
[evidence](../../SOURCES.md#client-tls-mode-2026-10-01).

The contract below was registered before implementation, in commit `053b858`.
Source and layout facts are from the pinned tree `e2104734a9` and the debug file
of packaged build `2ab960fa…` (SHA-256 `92a14f17…`).
[Pre-registration P23](../../02-RESEARCH-PARAMETERS.md#p23--does-each-activity-record-state-how-tmm-handled-client-tls).

## Why this comes before identity

The activity hooks see HTTP and JSON only when TMM parses plaintext. A deployment
can give TMM plaintext in two ways, and it can also give TMM no plaintext:

| Client connection at TMM | Activity records | Identity that a later step can bind |
|---|---|---|
| TMM ends TLS (client SSL filter) | Yes | A client certificate that TMM verified, or a token/proof in the request |
| Plain HTTP arrives at TMM | Yes | Only what an earlier hop forwards; trusted only if that hop is authenticated |
| TLS passes through TMM without decryption | No | None at the agent level |

So an identity claim is valid only when the record states which case applies.
This page adds that statement to each combined activity record. It does not add
identity.

## Source facts that set the design

- Each client connection has a chain of filter nodes. Start at
  `connflow.bottom_node` (+80) and follow `hudnode.above` (+24). TMM's own
  lookup, `proxy_get_node()` (`hudproxy.c:6373`), walks the same chain.
- The filter for a node is `hudnode.private` (+48) minus 136
  (`HUDNODE_FILTER`, `hudfilter.h:378`). The type pointer is the first word
  of `hudfilter.base` (filter +64). The type name is the first word of
  `struct hud_typeid`. The client SSL type name is `"SSL"` (`ssl.c:171`).
- The type objects are thread-local (`RTTHREAD`, `modules.h:388`). A probe
  therefore compares the name bytes, not a fixed type address.
- The SSL state is the node context, `hudnode.ctx` (+64), valid only when
  `f_active` and `f_ctx` (word +44, bits 22 and 23) are set (`hudfilter.h:370`).
- In `struct ssl_pcb`: `entity` (+12 bit 0, 1 = client side), `passthru`
  (+12 bit 16), `hsok` (+12 bit 26), `pcm` (+4 bits 15–16),
  `vfyresult` (+0 bits 22–28), `peercertchain` (+104), `suite` (+520,
  16 bytes; `id` at +8, `proto` at +12 bits 8–11), `allow_nonssl` (+40 bit 20).
- `ssl_hs_finish()` (`ssl_hs.c:1604`) can free `peercertchain` after the first
  handshake (`:1675-1683`). After that, `peercertchain == NULL` does not mean
  "no certificate". Only `vfyresult`, `pcm` and `hsok` stay valid for the
  life of the connection.

## Contract

Add one TLS-mode reading to the client side of each activity exchange, at the
existing HTTP entry (`hud_aimcp_handler`). For a server-side record, read the
client flow found by the existing symmetric peer check. Never read the
server-side SSL filter as client TLS.

Walk at most 16 nodes. Classify the client connection as one of:

| `tls_mode` | Condition |
|---|---|
| `terminated` | One SSL node, client entity, active context, `hsok` set, `passthru` clear |
| `ssl_filter_not_decrypting` | One SSL node, client entity, but `hsok` clear or `passthru` set |
| `no_ssl_filter` | Complete walk to the end of the chain with no SSL node |
| `unknown` | Read failure, walk limit reached, more than one SSL node, wrong entity, inactive context or other inconsistency |

For `terminated`, the probe exports raw facts only: protocol number and
cipher-suite ID from `ssl_pcb.suite`, `pcm`, `vfyresult`, and presence bits.
The exporter derives the certificate state off the data path.

Two source facts constrain that derivation:

- `vfyresult` starts at 0 (`SSL_VFY_OK`) after `memset` (`ssl.c:3703`). Under
  REQUEST with no certificate, the handshake can finish without setting it
  (`ssl_hs.c:6436-6444`). So `vfyresult == 0` alone is **not** verification.
- `ssl_hs_finish()` frees the chain when a session exists, or on TLS 1.3 without
  `retain_certificate`. With `retain_certificate`, `ssl_shim.c:4339-4344` saves the
  certificate message in `ssl_session.certmsg` (session +216). TMM's own
  certificate count uses the same fallback (`ssl_shim_check_peercert`,
  `ssl_shim.c:3144`).

So the probe reports `chain_present` (`peercertchain` +104), `session_cert_present`
(`session` +80, then `certmsg` +216) and `retain_certificate` (profile at
`ssl_pcb.prf` +72, word +716 bit 19). The exporter derives `client_certificate`:

| Value | Condition |
|---|---|
| `not_requested` | `pcm` IGNORE |
| `verified` | requested, a presence bit set, `vfyresult` 0 |
| `failed` | requested, a presence bit set, `vfyresult` not 0 (code kept) |
| `none_observed` | requested, no presence bit, `retain_certificate` set |
| `unknown` | anything else, including `retain_certificate` clear |

`none_observed` is not proof that no certificate was sent. Resumption bits
(`st_resume`, `ss_resume`) are reported; resumed connections stay outside the
qualified scope.

`no_ssl_filter` does **not** mean "plaintext from the client". It means TMM had no
client SSL filter. An HTTP record on such a connection shows that TMM parsed
HTTP; the TLS state before TMM is unknown. Passthrough connections produce no HTTP
record, so this probe cannot report them. Name that gap rather than inferring
passthrough from silence.

The reading is evidence of a TMM state, not identity. `client_cert_verified`
is TMM's verify result; it does not name a subject. A later identity step must
read and bind the certificate subject separately.

## Wire format and exporter

Read TLS state once per exchange: at the client-side request-header event
(`HUDEVT_REQUEST`, code 142), the same event that confirms the exchange. Other
HTTP events carry `not_applicable`. The HTTP record becomes ABI 2, 128 bytes:
the ABI 1 fields plus a 32-byte TLS block. ABI 1 decoding is unchanged for the
standalone response probe. The exporter copies the block to
`transport.client_tls` in the combined record and keeps `identity_binding: unknown`. If the client-side readings within one exchange
disagree, the exporter reports `transport.client_tls.status: conflicting` and
does not choose one.

## Falsifiers

Reject the implementation if any of these occur:

1. A connection through a client SSL profile is classified other than
   `terminated`, or a plain virtual server is classified other than
   `no_ssl_filter`.
2. The server-side SSL filter (a server SSL profile toward the backend) causes a
   `terminated` reading for the client side.
3. `client_certificate` is `verified` for an untrusted certificate, a missing
   certificate under REQUEST, or a profile that does not request one.
4. The reported protocol or cipher ID differs from the client's own record
   of the negotiated values (`ssl.SSLSocket.version()` / `cipher()`).
5. A walk loop, a node above the limit, an unreadable pointer, a context flag
   cleared or a second SSL node gives anything other than `unknown`.
6. A combined record gets an identity, or the exporter chooses a value when
   readings conflict.
7. Any existing activity check (ten combined exchanges, replay, page sizes,
   mutations) changes its result.

## Tests

- **Native:** synthetic chains for each class, both entity values, 16/17 nodes,
  a cycle, each unreadable pointer and each cleared flag; pinned GCC/clang
  interpreter and JIT; pinned PREVAIL with the 256-byte stack limit.
- **Live, isolated fixture, packaged build `2ab960fa…`:** three AIMCP virtual
  servers on one worker. (a) plain; (b) client SSL, no client certificate;
  (c) client SSL with `peer_cert_mode` REQUEST and a fixture CA, exercised with
  a trusted certificate, an untrusted certificate and no certificate. Run TLS 1.2
  and TLS 1.3. Keep-alive and concurrent clients on (b). Compare every reading
  with the client's own TLS record. Restore the hooks, archive and remove the
  fixture. Retain failed attempts.

## Scope limit

A pass establishes that each combined record states TMM's client-side SSL
filter state on one worker for HTTP/1 in this fixture. It does not establish
identity, certificate subjects, TLS state before TMM, passthrough detection,
HTTP/2, multiple workers, session resumption behavior or data-path cost.

## Measured result

Live attempt 02, packaged build `2ab960fa…`, artifact `a15f5135…` (186,704 bytes).
Every row is one combined exchange; the client column is the fixture client's
own `ssl` record.

| Case | `mode` | Protocol, cipher | `peer_cert_mode` | `client_certificate` | Verify code |
|---|---|---|---|---|---|
| Plain | `no_ssl_filter` | none (client used no TLS) | – | – | – |
| Client SSL | `terminated` | TLS 1.2 `0xc02f`; TLS 1.3 `0x1301` | ignore | `not_requested` | 0 |
| REQUEST, trusted certificate | `terminated` | 1.2 and 1.3 | request | `verified` | 0 |
| REQUEST, untrusted certificate | `terminated` | 1.2 and 1.3 | request | `failed` | 20 |
| REQUEST, no certificate | `terminated` | 1.2 and 1.3 | request | `none_observed` | 50 (1.2), **0 (1.3)** |
| Keep-alive, three requests | `terminated` | 1.3 | ignore | `not_requested` | 0 |
| Four concurrent connections | `terminated` | 1.2 | ignore | `not_requested` | 0 |

The plain chain had six filter nodes; each client-SSL chain had seven. Hook calls:
32 JSON and 362 HTTP, with zero VM errors and zero safe returns. Replay with
one-row pages gives identical combined records. Both hooks were patched and
restored; the TMM process and binary stayed the same with zero restarts. The
fixture was archived (eight files) and removed.

**The TLS 1.3 no-certificate row confirms the registered premise.** TLS 1.3
gives verify code 0 with no certificate, the same value as success. A probe
that used the verify code alone would report `verified`. The derivation
requires a presence bit, so it reports `none_observed`.

Native checks: pinned PREVAIL passes both entries; GCC and clang pass in
interpreter and JIT. Chains test each class, the 16/17-node limit, a cycle, five
unreadable pointers, an unreadable type and node, each cleared context flag, a
server-side SSL entity and two SSL filters. Each failure gives `unknown` with a
reason, never a class. The existing combined-activity checks still pass on the
measured 2026-09-30 journal.

Retained failures: builds 01–05 (sign comparison, loop unroll, missing header,
test setup, old parser path) and live attempt 01 (pylint, before any arm).

### Limits

- One worker, HTTP/1, one fixture. HTTP/2, multiple workers and data-path cost
  are not tested.
- `no_ssl_filter` means TMM had no client SSL filter. It does not prove the
  client sent plaintext; an earlier hop may have ended TLS.
- Passthrough produces no HTTP record, so this probe cannot detect it.
- A certificate state other than `unknown` needs `retain_certificate` (TMM's
  default) or a chain not yet freed. Session resumption was disabled in the
  fixture and stays unqualified.
- `verified` is TMM's verify result. It names no subject. Identity binding is
  the next step: read the certificate subject, and bind it only when the record
  shows `terminated` and `verified`.
- The client's TLS record is fixture code (SELF), not an independent audit.

### Repeat

On the build box, from a source snapshot containing this repository's
`substrate/` and `env/` files:

```sh
R=/home/starin/eob-config-20260925; P=$R/programs-package-01
python3 SOURCE/env/ai-traffic/activity_program_build.py --source SOURCE \
  --output $R/tls-mode-build-NEW --package $P/image-context --sign \
  --debug $P/debug/usr/lib/debug/usr/bin/tmm64.no_pgo.debug
python3 $R/json_initialization_fixture.py --package $P create --output CREATE.json \
  --collector-image sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054 \
  --collector-source NEW_SOURCE_DIR
python3 $R/json_initialization_live.py --run NEW --artifact-dir tls-mode-build-NEW \
  --image-build $R/collector-image-02/image-build.json --source-dir NEW_SOURCE_DIR \
  --output LIVE.json --tls-mode
python3 $R/json_initialization_fixture.py --package $P archive-cleanup --live LIVE.json \
  --archive ARCHIVE.tar.gz --output CLEANUP.json \
  --collector-image sha256:26f3184a4e3fe96b61f780761497933facc385f3d62d6f1cf66f04e56abd5054 \
  --collector-source NEW_SOURCE_DIR
```

The live and fixture scripts must be the versions in this repository; the shared
build-box directory keeps the 2026-09-30 versions, and the exact files used are
in `tls-mode-live-source-02/`. Use new names for every output.
