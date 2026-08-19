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
#include "ls_ctx_reg.h"
#include "ls_ctx_parse.h"
#include "ls_tp.h"

static unsigned long
build_parse(void *out, const unsigned long long *a)
{
    ls_ctx_build_parse((struct ls_ctx_parse *)out, (const void *)a[0], (const void *)a[2]);
    return sizeof(struct ls_ctx_parse);
}

static const struct ls_ctx_reg reg_parse = {
    "http_parse_client_headers", build_parse, sizeof(struct ls_ctx_parse),
    LS_TP_HOOK_HTTP1_HDRS
};
LS_CTX_REGISTER(reg_parse);

_Static_assert(sizeof(struct ls_ctx_parse) <= LS_CTX_OUT_MAX,
               "the parse record no longer fits the trampoline's ctx buffer");
