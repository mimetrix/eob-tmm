#include "ls_ctx_http_psm.h"
/* memory-safe throughout -- only the loop bound is attacker-influenced.
   Isolates the TERMINATION gate from the memory-safety gate. */
__attribute__((section("filter/folded_loop"), used))
unsigned long long shield(struct ls_ctx_http_psm *c)
{
    unsigned long long s = 0;
    for (unsigned int i = 0; i < c->name_len; i++)
        s += i;
    return s & 1;
}
