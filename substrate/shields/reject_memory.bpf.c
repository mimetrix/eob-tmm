#include "ls_ctx_http_psm.h"
__attribute__((section("fentry/reject_memory"), used))
unsigned long long shield(struct ls_ctx_http_psm *c)
{
    unsigned long long s = 0;
    for (unsigned int i = 0; i < c->name_len; i++)   /* unbounded: name_len is attacker-influenced */
        s += *(unsigned char *)(c->ptlp_name + i);   /* and chases a raw pointer */
    return s;
}
