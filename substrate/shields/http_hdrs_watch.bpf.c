/* tmm:l7:http_headers --- counts malformed requests, per request, inside TMM.
 *
 * The first program in this repo that reads TMM state which has actually been
 * written. Every predecessor either ignored its input (demo_pass) or read a
 * struct at a function's entry, before the function filled it --- which returned
 * zeros, correctly, and taught us that a tracepoint has to be placed rather than
 * attached.
 *
 * WHAT IT ANSWERS. "How many requests this interval were rejected or malformed,
 * and in which way." TMM computes that per request and keeps none of it. With
 * the host counting selections, safe_returns becomes the malformed count and
 * fired the total --- a ratio from two counters TMM already reports, needing no
 * ring, no map and no helper.
 *
 * HOW IT IS VALIDATED. Not by inspection. Each row below is an input we send and
 * a counter movement we predict first:
 *
 *     curl http://vip/               fired+1  safe_returns+0
 *     curl -X BOGUS http://vip/      fired+1  safe_returns+1   (reason=METHOD)
 *     curl -H ... x200               fired+1  safe_returns+1   (reason=HEADER_NUMBER)
 *
 * A tracepoint that cannot be fired on demand cannot be validated, and one whose
 * expected value is read off afterwards has not been tested at all.
 */
#include "ls_tp_http_bpf.h"

__attribute__((section("fentry/tmm_l7_http_headers"), used))
unsigned long long
shield(struct ls_tp_http_hdrs *c)
{
    /* MALFORMED: the parser found a protocol violation.
     *
     * Two earlier versions of this predicate were wrong, and both looked right:
     *
     *   reject_reason != 0    never assigned inside http_process_client_headers,
     *                         so it reads 0 even on a refused request.
     *   invalid_flags != 0    HTTP/2+3 pseudo-header validity; never written on
     *                         the 1.x path, so it read uninitialised memory. It
     *                         produced the RIGHT COUNT for the wrong reason.
     *   err != 0              `err` is reassigned a dozen times after the parse,
     *                         and ERR_MORE_DATA is 17 --- so this counts every
     *                         header block spanning two packets as a fault.
     *
     * parse_err is snapshotted straight out of the parser, and the classes are
     * enumerated rather than range-tested because ERR_MORE_DATA sits above them. */
    if (LS_TP_MALFORMED(c))
        return LS_SAFE_RETURN;

    return LS_FALLTHROUGH;
}
