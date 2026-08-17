/* ls_flow_cookie.h --- the STDINC-safe half of ls_flow_cookie.c.
 *
 * Deliberately declares NO TMM type. ls_tramp.c is compiled STDINC and must stay
 * that way; the flow is passed as void* and comes back as a scalar. Same split as
 * ls_ctx_alpn_abi.h, and for the same reason.
 */
#ifndef LS_FLOW_COOKIE_H
#define LS_FLOW_COOKIE_H

#include <stdint.h>

/* TMM's own cookie for this flow, or 0 when there is no flow. Zero is a legitimate
 * answer, not a failure --- flow_table.c rejects flows before one exists, and
 * rst_why() itself reports those with a zero cookie. */
uint64_t ls_uflow_cookie(void *uf);

#endif /* LS_FLOW_COOKIE_H */
