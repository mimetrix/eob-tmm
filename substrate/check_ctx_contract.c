/* Regression for CONTESTED-PREMISES.md §17. Exercise the real C dispatchers at
 * their VM boundary; no TMM or assembly required. The stand-in program checks
 * the complete verifier-visible region, then overwrites it. Repeated calls
 * must get fresh zeros, and program writes must not change the saved registers
 * or exit shadow frame. Run with ASan too: passing a length of 96 alone is not
 * proof that the caller actually allocated 96 bytes.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ls_arm.h"
#include "ls_fexit.h"
#include "ls_vm.h"

/* The C exit dispatcher only needs this symbol's address, never executes it. */
char ls_fexit_stub[1];

static const uint64_t args[6] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
static int exit_context;
static enum ls_verdict verdict;
static unsigned calls;

uint64_t ls_vm_safe_value(int slot)
{
    assert(slot == 3);
    return 2;
}

enum ls_verdict ls_vm_call(int slot, void *ctx, size_t n)
{
    const unsigned char *bytes = ctx;
    uint64_t ret;
    size_t payload = exit_context ? 48 : 40;

    assert(slot == 3);
    assert(ctx != NULL);
    /* Independent literal: shrinking a shared constant must not shrink the test. */
    assert(n == 96);
    assert(memcmp(ctx, args, 40) == 0);
    if (exit_context) {
        memcpy(&ret, bytes + 40, sizeof ret);
        assert(ret == 0xBEEF);
    }
    for (size_t i = payload; i < 96; i++)
        assert(bytes[i] == 0);

    /* Includes bytes 88..95, the read accepted by the pinned verifier. */
    memset(ctx, 0xA5, 96);
    calls++;
    return verdict;
}

int main(void)
{
    struct ls_regs regs = {
        .r11 = 0x11, .r10 = 0x10, .rax = 0xAA,
        .r9 = 0xF6, .r8 = 0xE5, .rcx = 0xD4,
        .rdx = 0xC3, .rsi = 0xB2, .rdi = 0xA1,
    };
    const struct ls_regs original = regs;

    for (unsigned i = 0; i < 32; i++) {
        verdict = i % 2 ? LS_SAFE_RETURN : LS_FALLTHROUGH;
        struct ls_tramp_result r = ls_tramp_dispatch(3, &regs);
        assert(r.verdict == (int)verdict);
        assert(r.safe_value == (verdict == LS_SAFE_RETURN ? 2 : 0));
        assert(memcmp(&regs, &original, sizeof regs) == 0);
    }
    assert(calls == 32);
    struct ls_tramp_result r = ls_tramp_dispatch(3, NULL);
    assert(r.verdict == LS_FALLTHROUGH && r.safe_value == 0);
    assert(calls == 32);

    exit_context = 1;
    verdict = LS_SAFE_RETURN;       /* must be ignored by the exit path */
    ls_fexit_reset();
    for (unsigned i = 0; i < 32; i++) {
        uint64_t return_slot = 0x12345678;
        ls_fexit_enter(3, &return_slot, args);
        assert(return_slot == (uint64_t)(void *)ls_fexit_stub);
        uint64_t target = ls_fexit_leave((uint64_t)(void *)(&return_slot + 1), 0xBEEF);
        assert(target == 0x12345678);
        assert(g_ls_fexit_log[i].retval == 0xBEEF);
        assert(memcmp(g_ls_fexit_log[i].args, args, sizeof args) == 0);
    }
    assert(calls == 64);
    assert(g_ls_fexit_exits == 32 && g_ls_fexit_desync == 0);
    puts("ok    context contract: entry + exit, 96 bytes, zero tails, isolated writes, repeated calls");
    return 0;
}
