/* tmm:l7:http_headers --- counts WAIVED requests: malformed AND forwarded anyway.
 *
 * This is the class with no existing observability in TMM at all. When
 * passthru_unknown_method, passthru_excess_client_headers or
 * passthru_oversize_client_headers is set, a request TMM has ALREADY JUDGED
 * malformed is proxied to the origin. Because it is a configured waiver rather
 * than an error, nothing logs it: no reset, no error counter, no log line. The
 * only record that it happened is the config, which says it may happen --- not
 * that it did, or how often, or to which origin.
 *
 * Refused traffic at least leaves a reset behind. Waived traffic leaves nothing,
 * which makes it the more useful thing to count and the harder one to notice is
 * missing.
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
