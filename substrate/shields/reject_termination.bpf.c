#include "ls_ctx_http_psm.h"
/* Loop with a data-dependent, non-closed-form body so -O2 cannot fold it.
   Memory-safe: reads only within ctx. Only the trip count is unbounded. */
__attribute__((section("fentry/reject_termination"), used))
unsigned long long shield(struct ls_ctx_http_psm *c)
{
    unsigned long long h = 1469598103934665603ULL;
    for (unsigned int i = 0; i < c->name_len; i++) {
        h ^= (h >> 7) + i;
        h *= 1099511628211ULL;
    }
    return h & 1;
}
