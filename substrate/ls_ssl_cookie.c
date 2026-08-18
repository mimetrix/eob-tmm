/* The ssl-world half of the ssl__err cookie derivation.
 *
 * Exists only to cross an include boundary. Reaching a flow from a struct ssl_ctx
 * needs that struct's layout and CONNFLOW_COOKIE, both of which live in TMM's
 * -nostdinc world; the trampoline that calls this is STDINC. This file is compiled in
 * the ssl module's world and exposes one function whose signature contains no TMM
 * type at all, which is the whole of the crossing.
 *
 * Same shape as ls_ctx_alpn.c and ls_flow_cookie.c, for the same reason: only types
 * that are ABI-identical on both sides may cross.
 *
 * PLACEMENT. This lives in modules/hudfilter/ssl/ rather than base/ so it can include
 * "ssl.h" directly and inherit that module's include set. A copy in base/ would need
 * every -I the ssl module has, which is exactly the build-config guessing the STDINC
 * split exists to avoid.
 *
 * WHY CONNFLOW_COOKIE AND NOT UFLOW_COOKIE. struct ssl_ctx holds `struct connflow *cf`
 * --- a connflow, not a uflow. UFLOW_COOKIE's job is to expand a uflow into whichever
 * of the two it is and then call CONNFLOW_COOKIE; given a connflow already in hand,
 * calling CONNFLOW_COOKIE directly is both shorter and avoids constructing a uflow we
 * do not have. The value is identical for a connflow, which is the point.
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

#include <local/base/flow_table.h>

#include "ssl.h"
#include "ssl_magic.h"

#include "ls_ssl_cookie.h"

unsigned long long
ls_ssl_cookie(void *scv)
{
    const struct ssl_ctx *sc = (const struct ssl_ctx *)scv;

    /* THREE INDEPENDENT NULL CHECKS, not one. ssl__err runs on error paths, and each
     * of these is legitimately absent at some of the 475 call sites --- a record
     * rejected before a flow exists has no cf, and CONNFLOW_COOKIE dereferences cf to
     * read start_tick and bottom_node. Collapsing these into one test would fault on
     * exactly the paths this tracepoint is for. */
    if (sc == NULL)
        return 0;
    if (sc->cf == NULL)
        return 0;

    return (unsigned long long)CONNFLOW_COOKIE(sc->cf);
}
