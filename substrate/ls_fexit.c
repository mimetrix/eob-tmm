/*
 * ls_fexit.c --- the C half of the function-exit trampoline: the shadow stack.
 *
 * ls_fexit_x86_64.S calls exactly two functions here:
 *
 *   ls_fexit_enter(slot, args)  at the hooked function's ENTRY --- record the real
 *                               return address and hijack the stack slot.
 *   ls_fexit_leave(cur, retval) when the body RETURNS into the stub --- find the
 *                               matching frame (reclaiming any a non-local exit
 *                               skipped), run the exit program, hand back the real
 *                               return address.
 *
 * WHY THE SHADOW STACK IS KEYED BY THE STACK POINTER, not a plain LIFO push/pop.
 * A plain stack desyncs the instant a return is skipped --- a longjmp or a C++
 * exception unwinds past a hooked frame without running its `ret`, so its exit
 * stub never fires and its frame is never popped; the NEXT exit then pops a stale
 * frame and returns to the wrong address. Keying each frame to the address of the
 * slot we hijacked lets ls_fexit_leave discard every frame DEEPER than the one
 * actually returning (deeper == lower address; the stack grows down) before it
 * matches. This is the reclaim the Linux kernel's kretprobes does for exactly the
 * same reason. TMM itself has no longjmp and no C++ unwind (P8, on the build box),
 * so this is a backstop; a future exit hook on an unwind-traversable target is
 * refused at arm time instead.
 *
 * NOT re-entrant / single-core: one shadow stack per instance, no lock, because
 * TMM is run-to-completion and two invocations never overlap on a core --- the
 * same assumption the VM call path already makes (ls_vm.h).
 *
 * Status: candidate artifact, exercised by check_fexit.c. Not wired into TMM.
 */

#include <stdint.h>
#include <string.h>

#include "ls_fexit.h"

/* Bounded: overflow must degrade to "do not hijack" (a plain return), never grow
 * or crash. 512 is far past any real call depth under a single hooked chain. */
#define LS_FEXIT_DEPTH 512

struct ls_fexit_frame {
    uint64_t *slot;         /* address of the caller-return we overwrote (the key) */
    uint64_t  real_ret;     /* what was there --- where the function truly returns  */
    uint64_t  args[6];      /* rdi..r9 as captured at entry                         */
    uint64_t  seq;          /* which enter this was --- for the exit program/log    */
};

static struct ls_fexit_frame g_stack[LS_FEXIT_DEPTH];
static int      g_top;          /* number of live frames                            */
static uint64_t g_seq;          /* monotonic enter counter                          */

/* Observability for the harness AND the eventual `status` reply. Non-static so
 * check_fexit.c can read them directly. */
struct ls_fexit_event g_fexit_log[LS_FEXIT_LOG];
unsigned g_fexit_log_n;         /* how many exits recorded (capped at LS_FEXIT_LOG)  */
uint64_t g_fexit_exits;         /* total exits observed                              */
uint64_t g_fexit_reclaimed;     /* frames discarded as skipped (non-local exits)     */
uint64_t g_fexit_overflow;      /* enters that could not hijack (depth exceeded)     */
uint64_t g_fexit_desync;        /* leaves that found no matching frame (should be 0)  */

/* The exit STUB's address, defined in the assembly. Written into the hijacked
 * slot so the body's `ret` reaches it. */
extern char ls_fexit_stub[];

void
ls_fexit_reset(void)
{
    g_top = 0;
    g_seq = 0;
    g_fexit_log_n = 0;
    g_fexit_exits = g_fexit_reclaimed = g_fexit_overflow = g_fexit_desync = 0;
    memset(g_fexit_log, 0, sizeof g_fexit_log);
}

/*
 * At the hooked function's entry. `slot` is the address of its caller-return on
 * the live stack; `args` points at the six saved integer-argument registers.
 *
 * Record the frame, then overwrite *slot so the body returns into the stub. On
 * overflow we DO NOT hijack: the function returns normally, no exit fires, and
 * nothing is corrupted --- a bounded, safe degradation.
 */
void
ls_fexit_enter(uint64_t *slot, const uint64_t *args)
{
    if (g_top >= LS_FEXIT_DEPTH) {
        g_fexit_overflow++;
        return;                                 /* do not hijack: plain return */
    }
    struct ls_fexit_frame *f = &g_stack[g_top++];
    f->slot     = slot;
    f->real_ret = *slot;
    memcpy(f->args, args, sizeof f->args);
    f->seq = ++g_seq;

    *slot = (uint64_t)(void *)ls_fexit_stub;    /* the hijack */
}

/*
 * When the body returns into the stub. `cur` is rsp at stub entry --- which is
 * exactly (the hijacked slot's address) + 8, because the body's `ret` popped the
 * slot. So the frame that is actually returning has slot == cur - 8.
 *
 * Reclaim first: any frame whose slot is DEEPER (lower address) than the one
 * returning was skipped by a non-local exit --- discard it. Then the top frame
 * must be the match; pop it, run the exit program, return its real address.
 *
 * Fail-safe: if no frame matches (a desync we cannot resolve --- must not happen
 * for a hooked target under the arm-time rules), return `retval`. That is wrong
 * as an address, but this path is asserted-unreachable in the harness and the
 * real system refuses the hooks that could reach it.
 */
uint64_t
ls_fexit_leave(uint64_t cur, uint64_t retval)
{
    uint64_t *watermark = (uint64_t *)(cur - 8);

    while (g_top > 0 && g_stack[g_top - 1].slot < watermark) {
        g_top--;
        g_fexit_reclaimed++;
    }

    if (g_top == 0 || g_stack[g_top - 1].slot != watermark) {
        g_fexit_desync++;
        return retval;                          /* unreachable under arm-time rules */
    }

    struct ls_fexit_frame *f = &g_stack[--g_top];

    /*
     * THE EXIT PROGRAM RUNS HERE in the wired system: ls_vm_call(exit_slot, &ctx),
     * where ctx carries f->args (the entry arguments) and retval (the result).
     * The harness records the event instead, so the test can assert the program
     * would have seen the right arguments, return value, and ordering.
     */
    g_fexit_exits++;
    if (g_fexit_log_n < LS_FEXIT_LOG) {
        struct ls_fexit_event *e = &g_fexit_log[g_fexit_log_n++];
        e->seq    = f->seq;
        e->retval = retval;
        memcpy(e->args, f->args, sizeof e->args);
    }

    return f->real_ret;
}
