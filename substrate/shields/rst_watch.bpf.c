/* tmm:net:reset --- counts connection teardowns TMM attributed to a cause.
 *
 * Armed at rst_why()'s entry, where every reset in TMM is recorded with the file
 * and line of the decision. See substrate/ls_ctx_rst.h for why no other surface
 * can observe this: when the reset follows a failed parse, no HTTP event ever
 * fired, so no iRule runs and WASM has no model. The client sees a bare TCP reset.
 *
 * THE PREDICATE. Plain RST_WHY passes ERR_UNKNOWN(32); the RST_WHY_ERR and
 * RST_WHY_EXPIRE forms pass a real err_t. So `err != ERR_UNKNOWN` separates
 * teardowns TMM could attribute from the ones it could not, which is the first
 * question worth asking of a reset and is answerable from one field.
 *
 * The record carries file:line regardless, so a consumer can distinguish the 80
 * distinct RST_WHY sites on the HTTP path without the program needing to know
 * about any of them. The counter answers "how many were attributable"; the
 * records answer "which line decided, and why".
 */
#include "ls_ctx_rst_bpf.h"

__attribute__((section("fentry/rst_why"), used))
unsigned long long
shield(struct ls_ctx_rst *c)
{
    if (c->err != LS_ERR_UNKNOWN)
        return LS_SAFE_RETURN;

    return LS_FALLTHROUGH;
}
