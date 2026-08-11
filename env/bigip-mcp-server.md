# BIG-IP MCP Server — backlog item

**Intent:** get the F5 BIG-IP **Model Context Protocol (MCP) Server** up and
running. **Gated on** having a stable TMM somewhere to point it at — so
this comes *after* the build environment work in
[tmm-build-environment.md](tmm-build-environment.md).

## Source

Internal Confluence (space `ENGESS`, page id `1061416633`):

```
https://docs.f5net.com/spaces/ENGESS/pages/1061416633/F5+BIG-IP+Model+Context+Protocol+MCP+Server
```

## Access status — checked 2026-08-11

- `docs.f5net.com` resolves to **`172.25.8.129`** and is **network-reachable**
  from this sandbox.
- The page itself is **not readable anonymously**: returns `302` to
  `/login.action?...&permissionViolation=true`. That's Confluence
  Server/Data Center, so it wants an authenticated session, not an
  API token in a header by default.
- **Content not yet read.** Nothing below is derived from the page — it is
  all inference and needs replacing with the real thing.

To actually read it, one of:
- User pastes the relevant content into a session.
- A Confluence personal access token (Confluence DC supports PATs via
  `Authorization: Bearer <token>`) → then `curl` the REST API for the page
  body: `/rest/api/content/1061416633?expand=body.storage`.
- The `claude_ai_Atlassian` MCP connector is available in this session but
  unauthenticated, and it targets Atlassian **Cloud**; this is a
  self-hosted `f5net.com` instance, so it most likely won't reach it.

## What to find out from the page

Open questions to answer once the content is available — recorded now so
the read is efficient:

1. What the MCP server actually exposes as tools/resources — config
   read/write (`tmsh`/iControl REST), stats, logs, all of it?
2. **Where it runs** — on the BIG-IP itself, or as a sidecar/external
   process that talks to a BIG-IP over iControl REST? This determines
   whether "a stable TMM" means a full BIG-IP VE instance or just a
   reachable TMM endpoint.
3. Transport — stdio vs SSE/HTTP — and therefore how a client (e.g. Claude
   Code) would connect to it from this sandbox.
4. Auth model against the BIG-IP (admin credentials? token?).
5. Whether it needs a **licensed** BIG-IP — the July VE boot attempt ran
   unlicensed (see [04](bigip-ve-boot-2026-07-17.md)), and many
   iControl REST surfaces are limited without a license.
6. Minimum TMOS/BIG-IP Next version it supports — cross-check against
   whatever image the TMM build guidance recommends.
7. Whether it targets classic TMOS, BIG-IP Next, or **BNK** — relevant
   because BNK is one of this project's three target form factors (see
   [01](archive-eob-bigip/01-bigip-form-factors-and-ebpf-surface.md)).

## Why it's interesting for this project

An MCP server over BIG-IP is a **control-plane** interface — config and
telemetry via a structured API. This project's eBPF work is aimed at
**dataplane/TMM observability**, which standard kernel eBPF hooks can't
see (see the open question in [04](bigip-ve-boot-2026-07-17.md)).
Those are complementary, not overlapping: if the eBPF side can produce
TMM-level signal, an MCP server is a plausible way to *expose* it to an
agent alongside the existing config/stats surface. Worth keeping in view
while scoping the first eBPF use case, but **not** a prerequisite for it.
