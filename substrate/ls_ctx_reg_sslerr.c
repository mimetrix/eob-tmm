/* ls_ctx_reg_sslerr.c --- ssl__err registers its builder.
 *
 * ssl__err(sc, alert, __func__, __LINE__, msg, ...) --- 475 call sites. The message is the
 * FIRST VARARG, so it lands in r8, within the six registers the trampoline forwards; that is
 * the only reason this hook needed no change to the assembly.
 *
 * Note it is __func__ and not __FILE__ --- ssl__err does not pass a filename, and a builder
 * that assumed one would record a function name in a field labelled `file`.
 */
#include "ls_ctx_reg.h"
#include "ls_ctx_sslerr.h"
#include "ls_tp.h"

extern unsigned long long ls_ssl_cookie(void *sc);

static unsigned long
build_sslerr(void *out, const unsigned long long *a)
{
    ls_ctx_sslerr_build((struct ls_ctx_sslerr *)out, (unsigned int)a[1], (const char *)a[2],
                        (unsigned int)a[3], (const char *)a[4],
                        ls_ssl_cookie((void *)a[0]));
    return sizeof(struct ls_ctx_sslerr);
}

static const struct ls_ctx_reg reg_sslerr = {
    "ssl__err", build_sslerr, sizeof(struct ls_ctx_sslerr), LS_TP_HOOK_SSLERR
};
LS_CTX_REGISTER(reg_sslerr);

_Static_assert(sizeof(struct ls_ctx_sslerr) <= LS_CTX_OUT_MAX,
               "the sslerr record no longer fits the trampoline's ctx buffer");
