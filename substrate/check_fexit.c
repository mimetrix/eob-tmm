/*
 * check_fexit.c --- proves the function-EXIT trampoline on real x86-64 hardware.
 *
 * Arms four stand-ins (fexit_victims.S) whose entry pads call ls_fexit_entry, and
 * asserts the properties an exit hook must have:
 *
 *   A  the caller still receives the true return value  (the stub is transparent)
 *      and the exit program is handed that value AND the entry arguments;
 *   B  a nested armed call unwinds its exits LIFO (inner before outer);
 *   C  deep recursion stays synced --- n+1 exits, deepest returns first;
 *   D  a return SKIPPED by a longjmp is reclaimed, and the next exit is correct.
 *
 * D is the one the whole shadow-stack-keyed-by-SP design exists for. Each stand-in
 * is armed at a per-slot exit trampoline (ls_fexit_slot<n>, folded into
 * trampoline_x86_64.S). Build:
 *   gcc -O2 -fcf-protection=branch -o check_fexit \
 *       check_fexit.c ls_fexit.c ls_tramp.c trampoline_x86_64.S fexit_victims.S
 */

#include <stdint.h>
#include <stdio.h>
#include <setjmp.h>

#include "ls_fexit.h"

/* Linking the whole trampoline_x86_64.S pulls in the ENTRY slots' call to
 * ls_tramp_dispatch (ls_tramp.c), which references ls_vm_call. The fexit path
 * never reaches it; this stub only satisfies the linker. */
int ls_vm_call(int slot, void *ctx, unsigned long n) { (void)slot; (void)ctx; (void)n; return 0; }

extern uint64_t xv_leaf(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
extern uint64_t xv_mid (uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
extern uint64_t xv_rec (uint64_t);
extern uint64_t xv_jumps(void *);
extern uint64_t xv_outer(void);

static jmp_buf g_jb2;
static volatile uint64_t g_sink;

/* Deeper than the setjmp in mid_setjmp, so the skipped xv_jumps frame is ON TOP
 * of the shadow stack when xv_outer's exit later fires. noinline + using the
 * result keep it from being tail-called (which would reuse the return slot). */
static __attribute__((noinline)) void inner_chain(void)
{
    g_sink += xv_jumps(g_jb2);      /* armed; longjmps back to mid_setjmp; never returns */
}

/* Called from xv_outer's asm body (hence external linkage). setjmp sits BELOW
 * xv_outer and ABOVE xv_jumps; the longjmp returns control here, then normally up
 * into xv_outer, whose exit then fires with the stale inner frame on top. */
void mid_setjmp(void)
{
    if (setjmp(g_jb2) == 0)
        inner_chain();
}

static int fails;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("  FAIL %s\n", (msg)); fails++; } \
    else         { printf("  ok   %s\n", (msg)); } \
} while (0)

int
main(void)
{
    uint64_t r;

    puts("A --- leaf: return capture + transparency + entry args");
    ls_fexit_reset();
    r = xv_leaf(0xA1, 0xB2, 0xC3, 0xD4, 0xE5);
    printf("    ret=%#llx exits=%llu reclaimed=%llu desync=%llu\n",
           (unsigned long long)r, (unsigned long long)g_ls_fexit_exits,
           (unsigned long long)g_ls_fexit_reclaimed, (unsigned long long)g_ls_fexit_desync);
    CHECK(r == 0x1EAF, "A caller receives the real return value (stub transparent)");
    CHECK(g_ls_fexit_exits == 1 && g_ls_fexit_log_n == 1, "A exactly one exit observed");
    CHECK(g_ls_fexit_log[0].retval == 0x1EAF, "A exit program sees the return value");
    CHECK(g_ls_fexit_log[0].args[0] == 0xA1 && g_ls_fexit_log[0].args[4] == 0xE5,
          "A entry arguments captured and carried to the exit");
    CHECK(g_ls_fexit_log[0].slot == 1, "A the exit-program slot is carried (leaf armed at 1)");
    CHECK(g_ls_fexit_reclaimed == 0 && g_ls_fexit_desync == 0, "A no reclaim, no desync");

    puts("B --- nested: xv_mid calls xv_leaf, both armed");
    ls_fexit_reset();
    r = xv_mid(0x11, 0x22, 0x33, 0x44, 0x55);
    printf("    ret=%#llx exits=%llu\n", (unsigned long long)r,
           (unsigned long long)g_ls_fexit_exits);
    CHECK(r == 0x1FAF, "B nested return propagates (mid = leaf + 0x100)");
    CHECK(g_ls_fexit_exits == 2, "B two exits");
    CHECK(g_ls_fexit_log[0].seq == 2 && g_ls_fexit_log[0].retval == 0x1EAF,
          "B inner (leaf) exits FIRST --- LIFO");
    CHECK(g_ls_fexit_log[0].slot == 1 && g_ls_fexit_log[1].slot == 0,
          "B each exit carries its own slot (leaf=1, mid=0)");
    CHECK(g_ls_fexit_log[1].seq == 1 && g_ls_fexit_log[1].retval == 0x1FAF,
          "B outer (mid) exits second");
    CHECK(g_ls_fexit_desync == 0, "B no desync");

    puts("C --- recursion: xv_rec(7), every level armed");
    ls_fexit_reset();
    r = xv_rec(7);
    printf("    ret=%llu exits=%llu reclaimed=%llu\n", (unsigned long long)r,
           (unsigned long long)g_ls_fexit_exits, (unsigned long long)g_ls_fexit_reclaimed);
    CHECK(r == 7, "C recursion returns n");
    CHECK(g_ls_fexit_exits == 8, "C n+1 exits");
    CHECK(g_ls_fexit_log[0].retval == 0 && g_ls_fexit_log[0].seq == 8, "C deepest returns first");
    CHECK(g_ls_fexit_log[7].retval == 7 && g_ls_fexit_log[7].seq == 1, "C shallowest returns last");
    CHECK(g_ls_fexit_reclaimed == 0 && g_ls_fexit_desync == 0, "C clean nesting, no reclaim");

    puts("D --- reclaim: a longjmp skips an inner exit; the outer exit must reclaim it");
    ls_fexit_reset();
    r = xv_outer();                 /* inner armed chain longjmps back into xv_outer's body */
    printf("    ret=%#llx exits=%llu reclaimed=%llu desync=%llu\n",
           (unsigned long long)r, (unsigned long long)g_ls_fexit_exits,
           (unsigned long long)g_ls_fexit_reclaimed, (unsigned long long)g_ls_fexit_desync);
    CHECK(r == 0x0117, "D outer returns correctly after a longjmp back into its body");
    CHECK(g_ls_fexit_exits == 1, "D only the outer exit fired (inner was skipped)");
    CHECK(g_ls_fexit_reclaimed == 1, "D the skipped inner frame was reclaimed (SP-keyed)");
    CHECK(g_ls_fexit_log[0].retval == 0x0117, "D the outer exit sees its own return value");
    CHECK(g_ls_fexit_desync == 0, "D reclaim resynced without desync");

    printf("\n  %s\n", fails
        ? "FAILURES --- exit trampoline NOT validated"
        : "exit trampoline validated: capture, transparency, nesting, recursion, reclaim");
    return fails ? 1 : 0;
}
