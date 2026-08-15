/* tmm:l7:http_headers --- counts WAIVED requests: malformed AND forwarded anyway.
 *
 * TWO CORRECTIONS TO WHAT THIS FILE ORIGINALLY CLAIMED. Both were asserted
 * without checking, and both are wrong:
 *
 * 1. "Nothing records a waiver." FALSE. mcp/stats.h exports
 *    passthrough_unknown_method, passthrough_excess_client_headers,
 *    passthrough_oversize_client_headers and siblings as UINT64 counters,
 *    incremented per waiver at http.c:6890-6915. Aggregate counts already
 *    exist. What does NOT exist is a per-request record: the counters say how
 *    many were waived, never WHICH request, what was malformed about it, or
 *    what the parse verdict was. That is a real gap and a much narrower one
 *    than "no observability at all".
 *
 * 2. "Set a passthru_* flag and this fires." NOT ON A REVERSE PROXY. Every
 *    client-side waiver is gated on proxy_type == TRANSPARENT; anywhere else
 *    the profile value is overridden and a config-time log fires instead:
 *
 *        if (proxy_type != TRANSPARENT && enabled == PASSTHROUGH) {
 *            enabled = ALLOW;
 *            HTTPERR_PROFILE_PROXY_LOG("passthrough.unknown_method");
 *        }
 *
 *    BNK is a reverse proxy, so this program CANNOT be demonstrated there. It
 *    verifies, it decodes, and it has never selected a live record.
 *
 * The class that does hold up on this deployment is `refused` --- see
 * http_hdrs_watch.bpf.c. Rejected requests never reach the origin, so no origin
 * log can contain them, and TMM keeps no per-request record of why.
 *
 * Load this INSTEAD of http_hdrs_watch to switch what safe_returns counts ---
 * same tracepoint, same record, different question. That is what makes the class
 * a load-time policy choice rather than something compiled into the data plane.
 */
#include "ls_tp_http_bpf.h"

__attribute__((section("fentry/tmm_l7_http_headers"), used))
unsigned long long
shield(struct ls_tp_http_hdrs *c)
{
    /* Both halves are required. Malformed alone is the superset; passthru alone
     * fires on waivers that had nothing to waive. */
    if (LS_TP_MALFORMED(c) && c->passthru != 0)
        return LS_SAFE_RETURN;

    return LS_FALLTHROUGH;
}
