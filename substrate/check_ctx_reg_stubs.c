/* Stubs for the TMM-side functions the ctx builders call, so check_ctx_reg can link and run
 * outside TMM. Each returns a value the builders must already handle:
 *
 *   ls_uflow_cookie / ls_ssl_cookie -> 0, which is a LEGITIMATE answer, not an error. Flows
 *       are rejected before one exists and ssl__err fires before a connflow is attached, so
 *       the builders are required to treat 0 as "no flow" rather than as a failure.
 *   ls_ctx_alpn_build_v -> 0, meaning "no ALPN list", which is the path that makes the ALPN
 *       builder decline. That is the branch worth exercising here.
 *
 * Registers NOTHING. check_ctx_reg.c counts LS_CTX_REGISTER uses across the substrate .c files and
 * compares that with the linked total, so a stub file that registered anything would break
 * the count it is helping to check.
 */
unsigned long long ls_uflow_cookie(void *uf) { (void)uf; return 0ull; }
unsigned long long ls_ssl_cookie(void *sc)   { (void)sc; return 0ull; }
int ls_ctx_alpn_build_v(void *out, void *sc) { (void)out; (void)sc; return 0; }
