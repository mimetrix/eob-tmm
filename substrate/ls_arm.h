/* ls_arm.h --- patched-entry hooking: arm/disarm a LIVE function.
 *
 * Live-SURFACE mechanics. `ls_` is the live surface embedded in the data
 * plane; these primitives are used by ANY consumer of it (CVE shielding is
 * consumer #1, with observability, steering and self-tuning as peers), which
 * is why this header is not named for the shield.
 *
 * The point of this mechanism is that arming happens while TMM is RUNNING and
 * traffic is flowing --- no rebuild, no restart. That is what makes a shield
 * "live". Arming at startup would need a restart and would defeat the purpose,
 * so the write goes through ls_swap_write5(), the kernel-proven text_poke_bp
 * protocol, which is safe against other cores executing the same bytes.
 */
#ifndef LS_ARM_H
#define LS_ARM_H
#include <stdint.h>

struct ls_tramp_result { int verdict; uint64_t safe_value; };

/*
 * The hooked function's saved argument registers, as the trampoline pushed them.
 *
 * ORDER IS THE STACK'S, NOT THE ABI'S. The trampoline pushes rdi,rsi,rdx,rcx,r8,r9
 * then rax,r10,r11, so in memory they appear in REVERSE: r11 lowest, rdi highest.
 * The layout below matches the stack exactly and the asm passes a pointer to it;
 * getting this backwards does not crash, it silently swaps arguments, which the
 * trampoline's own comments record as having happened once already.
 *
 * A POINTER RATHER THAN SIX VALUES, deliberately. rdi carries the slot, leaving five
 * registers for arguments, so a sixth would have landed on the stack --- and
 * rst_cause is the sixth. Passing the block means all six arrive and no future
 * signature change touches the assembly again.
 */
struct ls_regs {
    uint64_t r11;               /* +0   scratch, saved for safety           */
    uint64_t r10;               /* +8   scratch, saved for safety           */
    uint64_t rax;               /* +16  varargs vector count; unused here   */
    uint64_t r9;                /* +24  arg5  <-- rst_cause lives here      */
    uint64_t r8;                /* +32  arg4                                */
    uint64_t rcx;               /* +40  arg3                                */
    uint64_t rdx;               /* +48  arg2                                */
    uint64_t rsi;               /* +56  arg1                                */
    uint64_t rdi;               /* +64  arg0                                */
};

/* Named accessors, so no call site indexes the block by ABI position and gets the
 * reversal wrong. */
#define LS_ARG0(r) ((r)->rdi)
#define LS_ARG1(r) ((r)->rsi)
#define LS_ARG2(r) ((r)->rdx)
#define LS_ARG3(r) ((r)->rcx)
#define LS_ARG4(r) ((r)->r8)
#define LS_ARG5(r) ((r)->r9)

struct ls_tramp_result ls_tramp_dispatch(int slot, const struct ls_regs *regs);

/* single-writer forms (no concurrent executor; used only off the live path) */
int ls_arm(void *fn, void *trampoline);
int ls_disarm(void *fn);

/* LIVE forms --- safe while other cores are executing the target */
int ls_arm_live(void *fn, void *trampoline, int slot);
int ls_disarm_live(void *fn);

/* the safe swap: rewrite 5 bytes of executed code under contention */
int  ls_swap_write5(uint8_t *pad, const uint8_t bytes[5]);
void ls_swap_trap_install(void);
#endif
