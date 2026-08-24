/* ls_ctx_reg_parse.c --- http_parse_client_headers registers its builder.
 *
 * The hook the survey found to be 1:1 with requests on this traffic's path. Its record is
 * shared by the HTTP/1.x, /2 and /3 sites because all three fill ci->http, which is why one
 * builder covers a shape three call sites produce.
 *
 * NOTE the hook_id here is the 1.x one. The record LAYOUT is identical for h2 and h3, but
 * which fields are load-bearing is not --- the five f_invalid_* pseudo-header bits are
 * written only by http2/ and http3/ code and are uninitialised on the 1.x path. When an h2
 * or h3 entry is armed it registers its own hook id against its own function name, in its
 * own file, and nothing here changes.
 */
#include <stdio.h>
#include "ls_ctx_reg.h"
#include "ls_ctx_parse.h"
#include "ls_tp.h"

/* Refusals are COUNTED AND ANNOUNCED, not merely returned.
 *
 * Returning 0 makes the trampoline fall through without running the program, which is the
 * right disposition --- but on its own it is the original defect wearing a different hat: the
 * operator sees `fired` stay at zero under traffic and cannot tell whether the hook is cold,
 * the program is wrong, or the record was refused. So the first refusal says so once, and the
 * count keeps accruing after that. One fprintf in the lifetime of the process is not a
 * firehose; a per-invocation one on this path would be.
 *
 * The first CALL also announces whether tier 2 is armed for this build, because "the bounds
 * header was never generated" and "the bounds were checked and passed" are indistinguishable
 * from the outside, and that indistinguishability is exactly what CONTESTED-PREMISES.md 12 is
 * about. */
static unsigned long ls_ctx_parse_refused;   /* records declined as not trustworthy */

static unsigned long
build_parse(void *out, const unsigned long long *a)
{
    static int announced, warned;
    struct ls_ctx_parse *c = (struct ls_ctx_parse *)out;
    const void *a0 = (const void *)a[0];
    const void *a2 = (const void *)a[2];

    if (!announced) {
        announced = 1;
        fprintf(stderr, "ls_vm: parse ctx sanity: tier 1 on, tier 2 %s\n",
                LS_CTX_PARSE_GATED
                    ? "on (bounds from this build's debug info)"
                    : "OFF --- ls_ctx_parse_bounds.h was never generated for this build, so a "
                      "wrong offset is caught only when both source pointers are null. Run "
                      "substrate/check_ctx_parse.py --emit-bounds against the shipped debuginfo.");
    }

    ls_ctx_build_parse(c, a0, a2);

    if (!ls_ctx_parse_sane(c, a0, a2)) {
        ls_ctx_parse_refused++;
        if (!warned) {
            warned = 1;
            fprintf(stderr, "ls_vm: parse ctx REFUSED --- the record is not trustworthy, so no "
                            "program ran and no verdict was counted. A verdict over a record "
                            "that was never read is a fabricated measurement, not a cautious "
                            "one. Further refusals are counted silently.\n");
        }
        return 0;                      /* fall through without running the program */
    }
    return sizeof(struct ls_ctx_parse);
}

static const struct ls_ctx_reg reg_parse = {
    "http_parse_client_headers", build_parse, sizeof(struct ls_ctx_parse),
    LS_TP_HOOK_HTTP1_HDRS
};
LS_CTX_REGISTER(reg_parse);

_Static_assert(sizeof(struct ls_ctx_parse) <= LS_CTX_OUT_MAX,
               "the parse record no longer fits the trampoline's ctx buffer");
