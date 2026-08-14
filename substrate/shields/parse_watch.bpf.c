/* tmm:l7:parse_error --- the first program here that reads real TMM state.
 *
 * Every program armed before this one was demo_pass: it returned 0 and ignored
 * its input. The mechanism ran and reported nothing. This one reads the HTTP
 * parser's own view of a request and answers a question about it.
 *
 * WHAT IT SEES. A flat struct built by the host in the trampoline
 * (substrate/ls_ctx_parse.h), from struct http_parse_ctx and struct
 * http_parse_info at http_parse_client_headers --- the one function the traffic
 * provably executes 1:1 with requests. No pointers: eBPF cannot chase one, and
 * PREVAIL will not admit a program that tries, which is exactly why the
 * dereferencing happens in the host instead.
 *
 * WHAT IT ANSWERS. `invalid_flags` carries five parse-violation bits --- bad
 * method, scheme, path, status, authority. TMM computes these per request and
 * keeps no per-request record of them. So the question "is anything malformed
 * about this request, and in which way" is answerable inside TMM and not
 * currently answered anywhere.
 *
 * DISPOSITION. Returns LS_SAFE_RETURN when a violation is present, so the host
 * counts it in safe_returns; otherwise LS_FALLTHROUGH. In MONITOR mode the host
 * counts the selection and applies nothing, which is how this is armed --- the
 * program is an observer here, not a control. Arming it in ENFORCE on this hook
 * would skip the header parse, which is emphatically not what a tracepoint does.
 */
#include "ls_ctx_parse_bpf.h"

__attribute__((section("fentry/http_parse_client_headers"), used))
unsigned long long
shield(struct ls_ctx_parse *c)
{
    /* Any of the five parse-violation bits. The host is counting selections,
     * so this makes `safe_returns` a per-request count of malformed requests
     * while `fired` stays the total --- a ratio, from two counters TMM already
     * reports, with no ring and no helper. */
    if (c->invalid_flags != 0)
        return LS_SAFE_RETURN;

    return LS_FALLTHROUGH;
}
