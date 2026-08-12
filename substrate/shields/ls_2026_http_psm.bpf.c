#include "ls_ctx_http_psm.h"

/* CVE shape at src/modules/hudfilter/http/http_psm.c:806-808 --
 *     ptlp = flow_get_listener(cf)->prot_transfer_log_profile;   // may be NULL
 *     str  = ptlp->name;                                          // unchecked
 *     return append_fn(str, strlen(str), dest);
 * Every other use of that field in the tree NULL-checks it.
 * The shield restores the missing check and asks for the safe return.
 */
__attribute__((section("fentry/http_psm_profile_name_lookup"), used))
unsigned long long shield(struct ls_ctx_http_psm *c)
{
    if (c->ptlp == 0)
        return LS_SAFE_RETURN;
    if (c->ptlp_name == 0)
        return LS_SAFE_RETURN;
    if (c->name_len == 0)
        return LS_SAFE_RETURN;
    return LS_FALLTHROUGH;
}
