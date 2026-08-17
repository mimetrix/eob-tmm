/* ls_flow_cookie.c --- TMM's own flow identifier, lifted out for the reset record.
 *
 * WHY A SEPARATE FILE, when ls_tramp.c already has the pointer. ls_tramp.c is
 * compiled STDINC --- standard C, no TMM headers --- because it is the arch-generic
 * dispatcher and keeping TMM types out of it is what lets it be syntax-checked
 * standalone. UFLOW_COOKIE() is a statement-expression macro in base/flow_table.h
 * that calls const_uflow_expand() and needs `struct connflow` and `struct
 * streamflow`. Those cannot cross into a STDINC file.
 *
 * So this file is compiled in TMM's include world (no STDINC in filelist, same as
 * ls_prep.c) and exposes ONE function taking a void* and returning a scalar. Exactly
 * the arrangement ls_ctx_alpn.c uses for the ssl module: the include-world-specific
 * work happens here, and the dispatcher only ever sees flat integers.
 *
 * WHY TMM'S COOKIE RATHER THAN A 5-TUPLE HASH. The first plan was to read the
 * addresses and ports out of the flow and hash them. Reading TMM's own identifier is
 * better on every axis:
 *
 *   - No struct layout knowledge, so nothing to re-derive when the layout changes.
 *   - rst_why() ITSELF calls UFLOW_COOKIE(uf) immediately after its NULL check, on
 *     this exact pointer on this exact path. Safety here is not an assumption; it is
 *     the same call the function we are hooking already makes.
 *   - It is what the rest of TMM means by "this flow", so records correlate with
 *     anything else that speaks cookies rather than defining a private identity.
 *   - It carries no addresses. The record already exposes internal source paths,
 *     which ls_ctx_rst.h flags as a disclosure decision; adding client IPs to a
 *     stream that may leave F5 would be a much larger one. A cookie answers
 *     "same flow or not" while saying nothing about whose.
 *
 * WHAT IT IS NOT. Not an identity, not stable across a flow's lifetime beyond the
 * flow itself, and not comparable across TMM instances. It answers exactly one
 * question --- are these two records the same flow --- which is what turns "82 resets"
 * into "82 resets across 3 flows" and therefore into a diagnosis.
 */
#include <local/sys/cpu.h>
#include <local/sys/def.h>
#include <local/sys/err.h>
#include <local/sys/lib.h>
#include <local/sys/queue.h>
#include <local/sys/time.h>

#include <local/base/flow_table.h>

#include "ls_flow_cookie.h"

/*
 * Returns TMM's cookie for this flow, or 0 if there is none.
 *
 * A NULL uf is NORMAL, not an error: rst_why() has an explicit `if (uf == NULL)`
 * branch and reports the teardown anyway with a zero cookie. A reset can be
 * attributed to a code site without a flow ever existing --- flow_table.c rejects a
 * flow before one is created --- so 0 must mean "no flow", never "lookup failed".
 */
uint64_t
ls_uflow_cookie(void *uf)
{
    if (uf == NULL)
        return 0;

    return (uint64_t)UFLOW_COOKIE((union uflow *)uf);
}
