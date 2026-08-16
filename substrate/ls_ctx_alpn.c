/* The ssl-world half of the ALPN ctx builder.
 *
 * Exists only to cross an include boundary. ls_ctx_alpn.h is a static inline
 * that needs struct ssl_ctx, ssl_ext_get_by_type() and SSL_EXT_ALPN --- all in
 * TMM's -nostdinc world. The trampoline that has to call it is STDINC. This
 * file is compiled in the ssl module's world and exposes one void*-typed entry
 * point, which is the whole of the crossing.
 *
 * Same shape as ls_prep.c, and for the same reason: only types that are
 * ABI-identical on both sides may cross.
 *
 * NOTE ON PLACEMENT. This lives in modules/hudfilter/ssl/ rather than base/ so
 * it can include "ssl.h" directly and inherit that module's include set. A copy
 * in base/ would need every -I the ssl module has, which is exactly the kind of
 * build-config guessing the STDINC split exists to avoid.
 */
#include <local/sys/cpu.h>
#include <local/sys/debug.h>
#include <local/sys/def.h>
#include <local/sys/err.h>
#include <local/sys/ha.h>
#include <local/sys/hudconf.h>
#include <local/sys/lib.h>
#include <local/sys/linker_set.h>
#include <local/sys/opt.h>
#include <local/sys/queue.h>
#include <local/sys/time.h>
#include <local/sys/timer.h>
#include <local/sys/tmstat.h>

#include "ssl.h"
#include "ssl_magic.h"

#include <local/base/ls_ctx_alpn_abi.h>
#include "ls_ctx_alpn.h"

int
ls_ctx_alpn_build_v(void *out, void *sc)
{
    return ls_ctx_alpn_build((struct ls_ctx_alpn *)out, (struct ssl_ctx *)sc);
}
