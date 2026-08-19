/* ls_ctx_reg_alpn.c --- ssl_alpn_match registers its builder.
 *
 * THE ONE BUILDER THAT CAN DECLINE. The ALPN bytes are not an argument: ssl_alpn_match
 * derives them from `sc` in its first ten lines, and ls_ctx_alpn_build_v repeats that
 * derivation one step earlier, over in the ssl module's include world. When there is no ALPN
 * list to judge it returns 0, and returning 0 from here means FALL THROUGH WITHOUT RUNNING
 * THE PROGRAM --- a verdict about bytes that do not exist is noise, not a finding.
 *
 * The builder itself lives in modules/hudfilter/ssl/ls_ctx_alpn.c because it needs the ssl
 * world's types; only a flat-bytes function crosses. This file is the registration, on the
 * STDINC side with the rest of the set, and it touches nothing but that crossing.
 */
#include "ls_ctx_reg.h"
#include "ls_ctx_alpn_abi.h"
#include "ls_tp.h"

static unsigned long
build_alpn(void *out, const unsigned long long *a)
{
    if (ls_ctx_alpn_build_v(out, (void *)a[0]) == 0)
        return 0;                      /* no ALPN list --- decline, do not run */
    return LS_CTX_ALPN_SZ;
}

/* ALPN has no LS_TP_HOOK_* id: it was never wired to the ring, because its record is a
 * verdict input rather than a telemetry record. hook_id 0 is not a valid schema, so
 * ls_tp_schema_for refuses it and a consumer prints raw rather than misreading fields --- see
 * the default case there. Publishing is skipped for a zero id rather than guessed at. */
static const struct ls_ctx_reg reg_alpn = {
    "ssl_alpn_match", build_alpn, LS_CTX_ALPN_SZ, 0u
};
LS_CTX_REGISTER(reg_alpn);

_Static_assert(LS_CTX_ALPN_SZ <= LS_CTX_OUT_MAX,
               "the alpn record no longer fits the trampoline's ctx buffer");
