/* ls_ctx_reg.c --- the lookup over the registration set, and the count that proves it linked.
 *
 * There is deliberately nothing else here. This file must not know any hook's name: the
 * moment it does, it is the hand-written table ls_ctx_reg.h exists to avoid.
 */
#include "ls_ctx_reg.h"

#include <stdio.h>

unsigned
ls_ctx_reg_count(void)
{
    return (unsigned)(__stop_ls_ctx_regs - __start_ls_ctx_regs);
}

const struct ls_ctx_reg *
ls_ctx_reg_lookup(const char *hook)
{
    const struct ls_ctx_reg *const *p;

    if (hook == 0 || hook[0] == '\0')
        return 0;

    for (p = __start_ls_ctx_regs; p < __stop_ls_ctx_regs; p++) {
        const char *a = hook;
        const char *b = (*p)->hook;

        /* Open-coded rather than strcmp: this file is compiled into TMM and the comparison
         * is three lines. Exact match --- see the header on why a prefix match is a bug. */
        while (*a != '\0' && *a == *b) {
            a++;
            b++;
        }
        if (*a == '\0' && *b == '\0')
            return *p;
    }
    return 0;
}

/*
 * Report the count once, from startup.
 *
 * NOT AN ASSERTION, and that is a judgement rather than laziness. A zero count means the
 * linker dropped the section, and every typed hook then degrades to the generic
 * five-register ctx --- which is SAFE (no dereference) but silently loses the reset feed and
 * the TLS feed. Refusing to start TMM over it would be worse than the degradation. So it is
 * loud in the log, and substrate/check_ctx_reg.c fails the BUILD when the linked count
 * disagrees with the number of registrations in the sources, which is where a missing
 * section can still be caught without a running data plane at stake.
 */
void
ls_ctx_reg_report(void)
{
    unsigned n = ls_ctx_reg_count();
    const struct ls_ctx_reg *const *p;

    if (n == 0) {
        fprintf(stderr, "ls_vm: NO CTX BUILDERS LINKED --- the ls_ctx_regs section was "
                        "discarded. Every typed hook will fall back to the generic "
                        "five-register context, so the reset and TLS feeds will produce "
                        "no records. Programs still run and nothing is dereferenced.\n");
        return;
    }
    fprintf(stderr, "ls_vm: %u ctx builder(s) linked:", n);
    for (p = __start_ls_ctx_regs; p < __stop_ls_ctx_regs; p++)
        fprintf(stderr, " %s(%lu B,id=%u)", (*p)->hook, (*p)->size, (*p)->hook_id);
    fprintf(stderr, "\n");
}
