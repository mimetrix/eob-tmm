/* ls_ssl_cookie.h --- the STDINC-safe half of ls_ssl_cookie.c.
 *
 * Same split as ls_flow_cookie.h and for the same reason: ls_tramp.c is compiled
 * STDINC and must stay that way, so the ssl context crosses as void* and the cookie
 * comes back as a scalar. No TMM type is declared here.
 *
 * WHY A SECOND COOKIE FUNCTION RATHER THAN REUSING ls_uflow_cookie. rst_why receives
 * a `union uflow *` directly. ssl__err receives a `struct ssl_ctx *`, and reaching the
 * flow from it means knowing that struct's layout --- which lives in the ssl module's
 * include world, not in base/. So the entry point differs even though both end at the
 * same cookie value.
 */
#ifndef LS_SSL_COOKIE_H
#define LS_SSL_COOKIE_H

/* NO #include, deliberately --- see the note in ls_flow_cookie.h. This header is read
 * from both include worlds and `unsigned long long` is a builtin. */

/* TMM's own cookie for the flow this SSL context belongs to, or 0 when there is none.
 *
 * ZERO IS A LEGITIMATE ANSWER. ssl__err fires on paths where no connflow is attached
 * yet --- a malformed record rejected before the flow is set up, for instance --- so 0
 * means "no flow", never "lookup failed".
 *
 * The value is the SAME cookie the reset record carries for the same connection:
 * UFLOW_COOKIE expands to CONNFLOW_COOKIE(cf) for a connflow uflow, and this computes
 * CONNFLOW_COOKIE on the connflow the ssl context already holds. That is what lets a
 * TLS failure be correlated with the reset that followed it. For a streamflow (HTTP/2
 * stream) UFLOW_COOKIE additionally XORs the streamflow pointer, so the two differ
 * there --- a known limit rather than a silent one. */
unsigned long long ls_ssl_cookie(void *sc);

#endif /* LS_SSL_COOKIE_H */
