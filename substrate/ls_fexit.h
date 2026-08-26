/*
 * ls_fexit.h --- the function-exit trampoline's shadow-stack interface.
 *
 * The assembly (ls_fexit_x86_64.S) calls ls_fexit_enter / ls_fexit_leave; the
 * harness (check_fexit.c) reads the log and counters. See ls_fexit.c.
 */
#ifndef LS_FEXIT_H
#define LS_FEXIT_H

#include <stdint.h>

#define LS_FEXIT_LOG 64u        /* recent exits kept for inspection */

/* One observed exit: what the exit program would have been handed. */
struct ls_fexit_event {
    uint64_t seq;               /* which enter this paired with           */
    uint64_t retval;            /* the hooked function's return value      */
    uint64_t args[6];           /* rdi..r9 captured at entry               */
};

/* Called from the assembly. */
void     ls_fexit_enter(uint64_t *slot, const uint64_t *args);
uint64_t ls_fexit_leave(uint64_t cur, uint64_t retval);

/* Clear all state between test cases. */
void ls_fexit_reset(void);

/* Observability (defined in ls_fexit.c). */
extern struct ls_fexit_event g_fexit_log[LS_FEXIT_LOG];
extern unsigned g_fexit_log_n;
extern uint64_t g_fexit_exits;
extern uint64_t g_fexit_reclaimed;
extern uint64_t g_fexit_overflow;
extern uint64_t g_fexit_desync;

#endif /* LS_FEXIT_H */
