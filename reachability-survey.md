# Reachability survey — which data-plane functions fire on live BNK traffic

**RECORD, 2026-08-27, datkube image `df2e3a63`.** The point of a shield is to sit on a *reachable*
path; every prior CVE attempt died because a function that *looked* reachable in source (e.g.
`prot_transfer_log_profile`) fired **zero** times live. This replaces source-reading with
measurement: arm a candidate function, drive representative traffic, read the `fired` counter.

## Method
- **Vehicle:** one signed program (`probe_parser`) loaded into each of the 12 slots, then armed at a
  distinct candidate function. Which program runs is irrelevant to a fire count; monitor mode, so a
  wrong field read is harmless. (A no-op program can't be used yet — see finding 1.)
- **Batching:** 54 candidates from the hook index (`http_parse_*`, header/cookie handlers, `ssl_*`
  parse/alpn/sni/extension, `http2_parse_*`), 12 at a time, disarmed between batches.
- **Traffic:** all HTTP/1.1 methods, cookies, long/many headers, `--http1.0`, chunked bodies,
  malformed requests (bad method, oversized URI), and **TLS + ALPN via the tls-gateway
  (`11.11.11.97`)** and HTTP/2. Fire counts are per-batch, so compare within a batch, not across.

## Result — reachable surface (fired > 0)
```
ssl_fwdp_proxy_alpn                fired=670    
ssl_alpn_opaque_set                fired=670    
http_parse_response                fired=670    
http_parse_compile_node            fired=670    
http2_get_h2_headers               fired=670    
ssl_fwdp_alpn_set                  fired=432    
ssl_alpn_match                     fired=432    
http_parse_headers                 fired=432    
ssl_fwdp_sni_bypass_check          fired=354    
ssl_alpn_proto                     fired=354    
http_parse_server_headers          fired=354    
ssl_get_alpn_list                  fired=288    
ssl_fwdp_ss_txhello_flowopq_set    fired=288    
ssl_codec_parse                    fired=288    
ssl_check_xbuf_records             fired=288    
http_parse_trailer                 fired=288    
http_parse_tokens_dupsort          fired=288    
http_parse_ctx_init                fired=288    
http_parse_ctx_fini                fired=288    
ssl_ext_sni_alloc                  fired=269    
http_parse_trailer_headers         fired=269    
http_parse_get_headerid            fired=269    
http_parse_cookies                 fired=210    
http2_parse_frame_header           fired=210    
http_parse_client_headers          fired=144    
ssl_fwdp_ss_txhello_flowopq_is_set fired=125    
ssl_cert_extension_set             fired=125    
http_parse_server_headers_str      fired=125    
http_parse_count_index             fired=125    
http_header_count                  fired=125    
http2_parse_payload                fired=125    
ssl_fwdp_lookup_by_sni             fired=80     
ssl_alpn_opaque_get                fired=80     
http_parse_request                 fired=80     
http_parse_compare                 fired=80     
http2_add_recv_header              fired=80     
ssl_fwdp_clear_proxy_alpn          fired=0      
ssl_fwdp_alpn_disable_rengotiation fired=0      
ssl_fwdp_add_by_sni                fired=0      
ssl_ext_sni_free                   fired=0      
ssl_alpn_opaque_free               fired=0      
http_parse_tree_prioritize         fired=0      
http_parse_tree_free               fired=0      
http_parse_tree_create             fired=0      
http_parse_info_copy               fired=0      
http_parse_get_versionid           fired=0      
http_parse_get_methodid            fired=0      
http_parse_get_headerid_xb         fired=0      
http_parse_client_headers_str      fired=0      
http_parse_build_expr_profile      fired=0      
http_parse_build                   fired=0      
http_header_decrypt                fired=0      
http_header_append                 fired=0      
http2_parse_uri                    fired=0      
LIVE                               fired=NA     (LIVE)
LIVE                               fired=NA     (LIVE)
LIVE                               fired=NA     (LIVE)
LIVE                               fired=NA     (LIVE)
LIVE                               fired=NA     (LIVE)
LIVE                               fired=NA     (LIVE)
```

**The reachable surface spans three parser families, all security-relevant:** HTTP/1.1
(`http_parse_headers/cookies/server_headers/trailer/request/...`), **HTTP/2**
(`http2_parse_frame_header`, `http2_parse_payload`, `http2_get_h2_headers`), and **TLS/ALPN/SNI**
(`ssl_codec_parse`, `ssl_check_xbuf_records`, `ssl_alpn_match`, `ssl_get_alpn_list`,
`ssl_ext_sni_alloc`, `ssl_fwdp_sni_bypass_check`, …). TLS traffic through the tls-gateway is what lit
the `ssl_*` set — reachability is **config × traffic**, so driving the right listener matters as much
as arming the right function. Only 3 stayed at 0 (renegotiation / add-by-sni paths that need
specific config).

## Findings
1. **CO-RE refuses a zero-relocation program** (`ls_vm: refusing --- CO-RE relocation failed rc=-3`).
   A program that reads nothing has no `.BTF.ext`, and the relocator rejects it. Over-strict — a
   zero-relocation program should load. Worked around by using a real program as the survey vehicle;
   a small `ls_core_relo.c` fix belongs in the next build.
2. **TMM's git history does not tag data-plane CVEs.** Of 27 CVE-referencing commits, all are
   base-image / dependency CVEs (`f5-runtime-base-ubuntu`, `USN-7980`, `internal-schema`); **none**
   touch HTTP/SSL parser files, and no reachable function appears in a CVE-fix diff. F5 tracks its own
   code fixes by **internal IDs** (`BZ-`, `MBIP-`, `BIGGESTIP-`), not CVE IDs. So a CVE→function map
   **cannot** come from `git log --grep=CVE`; it needs external advisories cross-referenced with the
   code (or a public-CVE→internal-bug-ID bridge we do not have in-repo).
3. A few arms failed to resolve a name→address (`http_header_by_name`, `http_cookie_get`) — the index
   has the name but the loader refused; a quick diagnosis is owed.

## Next — CVE cross-reference
The reachable surface above is the target set. Matching requires **external** F5 BIG-IP advisories
(memory-safety CVEs in HTTP/HTTP2/TLS parsing) retrieved and cached under the evidence rules
(`SOURCES.md`), then mapped to a reachable area — the fix commit (via GitSwarm) names the function.
No CVE→function claim is asserted from memory.
