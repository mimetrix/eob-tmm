/* ls_ctx_reg_h2abort.c --- http2_stream_abort registers its builder.
 *
 * http2_stream_abort(stream, why, err): three direct arguments, nothing derived, nothing to
 * snapshot. The simplest builder in the set, and the only hook that passes all four
 * uniqueness tests --- its reason reaches no log, no iRule event and no trace in a
 * production build.
 */
#include "ls_ctx_reg.h"
#include "ls_ctx_h2abort.h"
#include "ls_tp.h"

static unsigned long
build_h2abort(void *out, const unsigned long long *a)
{
    ls_ctx_h2abort_build((struct ls_ctx_h2abort *)out, a[0], (const char *)a[1],
                         (unsigned int)a[2]);
    return sizeof(struct ls_ctx_h2abort);
}

static const struct ls_ctx_reg reg_h2abort = {
    "http2_stream_abort", build_h2abort, sizeof(struct ls_ctx_h2abort), LS_TP_HOOK_H2ABORT
};
LS_CTX_REGISTER(reg_h2abort);

_Static_assert(sizeof(struct ls_ctx_h2abort) <= LS_CTX_OUT_MAX,
               "the h2abort record no longer fits the trampoline's ctx buffer");
