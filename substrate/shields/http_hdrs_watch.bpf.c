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
    /* reject_reason is set on every path that refuses the request; the five
     * invalid_flags bits catch malformations the parser records without
     * rejecting outright. Either one puts the request in the counted set.
     *
     * Read as separate tests rather than folded together: they answer different
     * questions, and a later version that reports WHICH class will need them
     * apart anyway. */
    if (c->reject_reason != 0)
        return LS_SAFE_RETURN;

    if (c->invalid_flags != 0)
        return LS_SAFE_RETURN;

    return LS_FALLTHROUGH;
}
