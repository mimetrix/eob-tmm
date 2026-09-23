/*
 * ls_fexit.h --- the function-exit trampoline's shadow-stack interface.
 *
 * The per-slot exit trampolines (ls_fexit_slot<n>, in trampoline_x86_64.S) call
 * ls_fexit_enter / ls_fexit_leave; the harness (check_fexit.c) reads the log and
 * counters. See ls_fexit.c.
 *
 * All mutable state is a single per-instance block of g_ls_fexit_* globals ---
 * one VM per core-pinned run-to-completion TMM instance, so no lock, and the
 * whole set is what the TMM globals whitelist must carry (like g_ls_audit).
 */
#ifndef LS_FEXIT_H
#define LS_FEXIT_H

#include <stdint.h>
#include "ls_vm.h"

#define LS_FEXIT_LOG 64u        /* recent exits kept for inspection */

/* The exit payload retains arg[0..4] at bytes 0..39 and ret at bytes 40..47.
 * fexit/ selects the same 96-byte tracing descriptor as fentry/, so the rest
 * must also be allocated and zeroed before calling the program. */
struct ls_ctx_exit {
    uint64_t arg[5];            /* rdi..r8, as the entry ctx           */
    uint64_t ret;              /* the hooked function's return value  */
    uint64_t reserved[LS_TRACING_CTX_SIZE / sizeof(uint64_t) - 6];
};
_Static_assert(sizeof(struct ls_ctx_exit) == LS_TRACING_CTX_SIZE,
               "exit context must cover the verifier's tracing region");
_Static_assert(offsetof(struct ls_ctx_exit, ret) == 40,
               "exit return-value offset must not change");
_Static_assert(offsetof(struct ls_ctx_exit, reserved) == 48,
               "exit payload must remain 48 bytes");

/* One observed exit: what the exit program would have been handed, plus which
 * slot's program it was. */
struct ls_fexit_event {
    uint64_t seq;               /* which enter this paired with           */
    int      slot;              /* which exit-program slot                */
    uint64_t retval;            /* the hooked function's return value      */
    uint64_t args[6];           /* rdi..r9 captured at entry               */
};

/* Called from the per-slot exit trampoline. `slot` is which exit-program to run
 * at leave; `slot_addr` is the caller-return to hijack; `args` the saved rdi..r9. */
void     ls_fexit_enter(int slot, uint64_t *slot_addr, const uint64_t *args);
uint64_t ls_fexit_leave(uint64_t cur, uint64_t retval);

/* Clear all state between test cases (and at instance init). */
void ls_fexit_reset(void);

/* Per-instance state / observability (defined in ls_fexit.c). */
extern struct ls_fexit_event g_ls_fexit_log[LS_FEXIT_LOG];
extern unsigned g_ls_fexit_log_n;
extern uint64_t g_ls_fexit_exits;
extern uint64_t g_ls_fexit_reclaimed;
extern uint64_t g_ls_fexit_overflow;
extern uint64_t g_ls_fexit_desync;

#endif /* LS_FEXIT_H */
