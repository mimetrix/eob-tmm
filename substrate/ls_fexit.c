/*
 * ls_fexit.c --- the C half of the function-exit trampoline: the shadow stack.
 *
 * The per-slot exit trampolines (ls_fexit_slot<n>, trampoline_x86_64.S) call:
 *
 *   ls_fexit_enter(slot, slot_addr, args)  at the hooked function's ENTRY ---
 *       record the real return address (and which exit-program slot to run) and
 *       hijack the stack slot.
 *   ls_fexit_leave(cur, retval)  when the body RETURNS into the stub --- find the
 *       matching frame (reclaiming any a non-local exit skipped), run the exit
 *       program, hand back the real return address.
 *
 * WHY KEYED BY THE STACK POINTER, not a plain LIFO. A skipped return (longjmp or
 * a C++ exception unwinding past a hooked frame) never runs that frame's `ret`,
 * so its exit stub never fires and its frame is never popped; a plain stack would
 * then pop a stale frame and return to the wrong address. Keying each frame to
 * the hijacked slot's address lets ls_fexit_leave discard every frame DEEPER than
 * the one returning (deeper == lower address; the stack grows down) before it
 * matches --- the reclaim kretprobes does. TMM itself has no longjmp and no C++
 * unwind (P8, on the build box), so this is a backstop; a future exit hook on an
 * unwind-traversable target is refused at arm time instead.
 *
 * ONE INSTANCE, no lock: TMM is core-pinned and run-to-completion, so two
 * invocations never overlap on a core --- the same assumption ls_vm.h makes. All
 * state is g_ls_fexit_*, which the TMM globals whitelist carries as a set.
 *
 * Status: mechanism proven by check_fexit.c (arms stand-ins; capture,
 * transparency, nesting, recursion, longjmp-reclaim). Running the exit PROGRAM
 * (ls_vm_call on struct ls_ctx_exit) is fexit step #2; today leave records.
 */

#include <stdint.h>
#include <string.h>

#include "ls_fexit.h"

/* Bounded: overflow degrades to "do not hijack" (a plain return), never grows or
 * crashes. 512 is far past any real depth under a single hooked chain. */
#define LS_FEXIT_DEPTH 512

struct ls_fexit_frame {
    uint64_t *slot;         /* address of the caller-return we overwrote (the key) */
    uint64_t  real_ret;     /* what was there --- where the function truly returns  */
    uint64_t  args[6];      /* rdi..r9 as captured at entry                         */
    uint64_t  seq;          /* which enter this was                                 */
    int       prog_slot;    /* which exit-program to run at leave                   */
};

/* Per-instance state. Non-static: the whole g_ls_fexit_* set is what the TMM
 * globals whitelist must declare, and the harness reads the counters/log. */
struct ls_fexit_frame g_ls_fexit_stack[LS_FEXIT_DEPTH];
int      g_ls_fexit_top;        /* number of live frames                            */
uint64_t g_ls_fexit_seq;        /* monotonic enter counter                          */

struct ls_fexit_event g_ls_fexit_log[LS_FEXIT_LOG];
unsigned g_ls_fexit_log_n;      /* exits recorded (capped at LS_FEXIT_LOG)          */
uint64_t g_ls_fexit_exits;      /* total exits observed                             */
uint64_t g_ls_fexit_reclaimed;  /* frames discarded as skipped (non-local exits)    */
uint64_t g_ls_fexit_overflow;   /* enters that could not hijack (depth exceeded)    */
uint64_t g_ls_fexit_desync;     /* leaves that found no matching frame (must be 0)  */

/* The exit STUB's address (trampoline_x86_64.S), written into the hijacked slot. */
extern char ls_fexit_stub[];

void
ls_fexit_reset(void)
{
    g_ls_fexit_top = 0;
    g_ls_fexit_seq = 0;
    g_ls_fexit_log_n = 0;
    g_ls_fexit_exits = g_ls_fexit_reclaimed = g_ls_fexit_overflow = g_ls_fexit_desync = 0;
    memset(g_ls_fexit_log, 0, sizeof g_ls_fexit_log);
}

/*
 * At the hooked function's entry. `slot` is the address of its caller-return on
 * the live stack; `args` points at the six saved integer-argument registers;
 * `prog_slot` is which exit program runs at leave.
 *
 * Record the frame, then overwrite *slot so the body returns into the stub. On
 * overflow we DO NOT hijack: the function returns normally, no exit fires, and
 * nothing is corrupted --- a bounded, safe degradation.
 */
void
ls_fexit_enter(int prog_slot, uint64_t *slot, const uint64_t *args)
{
    if (g_ls_fexit_top >= LS_FEXIT_DEPTH) {
        g_ls_fexit_overflow++;
        return;                                 /* do not hijack: plain return */
    }
    struct ls_fexit_frame *f = &g_ls_fexit_stack[g_ls_fexit_top++];
    f->slot      = slot;
    f->real_ret  = *slot;
    memcpy(f->args, args, sizeof f->args);
    f->seq       = ++g_ls_fexit_seq;
    f->prog_slot = prog_slot;

    *slot = (uint64_t)(void *)ls_fexit_stub;    /* the hijack */
}

/*
 * When the body returns into the stub. `cur` is rsp at stub entry --- exactly
 * (the hijacked slot's address) + 8, because the body's `ret` popped the slot.
 * So the returning frame has slot == cur - 8.
 *
 * Reclaim first: any frame whose slot is DEEPER (lower address) than the one
 * returning was skipped by a non-local exit --- discard it. Then the top frame
 * must be the match; pop it, run the exit program, return its real address.
 *
 * Fail-safe: if no frame matches (a desync we cannot resolve --- must not happen
 * for a hooked target under the arm-time rules), return `retval`.
 */
uint64_t
ls_fexit_leave(uint64_t cur, uint64_t retval)
{
    uint64_t *watermark = (uint64_t *)(cur - 8);

    while (g_ls_fexit_top > 0 && g_ls_fexit_stack[g_ls_fexit_top - 1].slot < watermark) {
        g_ls_fexit_top--;
        g_ls_fexit_reclaimed++;
    }

    if (g_ls_fexit_top == 0 || g_ls_fexit_stack[g_ls_fexit_top - 1].slot != watermark) {
        g_ls_fexit_desync++;
        return retval;                          /* unreachable under arm-time rules */
    }

    struct ls_fexit_frame *f = &g_ls_fexit_stack[--g_ls_fexit_top];

    /*
     * THE EXIT PROGRAM RUNS HERE in the wired system (fexit step #2):
     *     struct ls_ctx_exit ctx;
     *     memcpy(ctx.arg, f->args, sizeof ctx.arg);   ctx.ret = retval;
     *     ls_vm_call(f->prog_slot, &ctx, sizeof ctx);
     * The harness records the event instead, so the test can assert the program
     * would have seen the right slot, arguments, return value, and ordering.
     */
    g_ls_fexit_exits++;
    if (g_ls_fexit_log_n < LS_FEXIT_LOG) {
        struct ls_fexit_event *e = &g_ls_fexit_log[g_ls_fexit_log_n++];
        e->seq    = f->seq;
        e->slot   = f->prog_slot;
        e->retval = retval;
        memcpy(e->args, f->args, sizeof e->args);
    }

    return f->real_ret;
}
