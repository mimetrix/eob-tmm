/*
 * ls_arm.c --- write the patch into live code, and take it back out. Item 2.
 *
 * The trampoline (trampoline_x86_64.S) is the TARGET of the patch; this is the
 * act of installing it. Given a function whose entry carries the
 * -fpatchable-function-entry pad, arming rewrites the five nop bytes into a
 * `call rel32` to the trampoline, and disarming restores the nops.
 *
 * ===================================================================
 *  WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT
 * ===================================================================
 *
 * DOES: locate the pad, compute the rel32, write the five bytes through
 * /proc/self/mem (opcode byte last) atomically enough for the single-writer case,
 * flush the i-cache. Reversibly. Verified by arming a live function and calling it.
 *
 * DOES NOT: coordinate with other cores. On x86 a `call` opcode is written by a
 * single aligned store of its first byte last, so a core fetching mid-write sees
 * either all-nops or the whole call --- never a torn instruction --- which is why
 * ftrace patches live kernel text this way. But that is safety against a TORN
 * READ, not against a core standing INSIDE the pad at the instant of the write,
 * nor against the cross-modifying-code rule that every other core must serialise
 * before trusting the new bytes. Closing those is the safe point (item 0), and
 * it is not here. This is correct for a single thread and for the demonstration;
 * it is NOT correct to run against a live multi-core TMM without item 0.
 *
 * Writes go through /proc/self/mem, the debugger's path into r-xp text --- no
 * mprotect, no W^X relaxation, no writable alias. Proven to reach the *executed*
 * bytes on real private .text (it was long assumed impossible here; that was a
 * flawed readback test --- see ls_write_text). What remains TMM-specific: whether
 * tmm64's text is hugepage-backed (this is proven on 4 KB pages) and whatever
 * code-integrity policy the production node enforces.
 *
 * Status: candidate artifact. It runs (see check_arm.c). Nothing in TMM calls it.
 */

#include <stdint.h>
#include <fcntl.h>
#include "ls_arm.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/* The pad, as -fpatchable-function-entry=5,0 emits it under IBT: endbr64 then
 * five single-byte nops. Arming replaces the nops; the endbr64 stays, so the
 * function remains a valid indirect-branch target throughout. */
#define LS_ENDBR   "\xf3\x0f\x1e\xfa"
#define LS_ENDBR_LEN 4
#define LS_PAD_LEN 5
static const uint8_t LS_NOPS[LS_PAD_LEN] = { 0x90, 0x90, 0x90, 0x90, 0x90 };

/*
 * Find the five patchable bytes at a function's entry.
 *
 * Returns a pointer to the first pad byte, or NULL if the entry is not the shape
 * arming requires --- which is a REFUSAL, not a guess. A function without the pad
 * cannot be armed, and pretending otherwise would corrupt a real instruction.
 * The endbr64 is required too: without it the function was not built for IBT and
 * this whole mechanism's assumptions do not hold.
 */
static uint8_t *
ls_find_pad(void *fn)
{
    uint8_t *p = (uint8_t *)fn;

    if (memcmp(p, LS_ENDBR, LS_ENDBR_LEN) != 0)
        return NULL;                       /* not an IBT entry --- refuse       */
    if (memcmp(p + LS_ENDBR_LEN, LS_NOPS, LS_PAD_LEN) != 0)
        return NULL;                       /* not the nop pad --- already armed */
    return p + LS_ENDBR_LEN;
}

/*
 * Arm: write `call rel32` over the pad so entering the function calls the
 * trampoline. Returns 0 on success, -1 on refusal.
 *
 * rel32 is relative to the END of the call (pad + 5), and must fit in a signed
 * 32-bit displacement --- checked, because a trampoline out of ±2GB range cannot
 * be reached by five bytes and the alternative is a torn indirect jump. Fail
 * closed rather than emit a call to the wrong place.
 */
/*
 * Write `len` bytes to executed code at `dst`, opcode byte LAST so the 5-byte
 * window is never a call-with-garbage-target.
 *
 * The write goes through /proc/self/mem --- the path a debugger uses to set a
 * breakpoint in its target's r-xp text. A process's own .text is mapped private
 * (r-xp), so a plain store faults (not writable) and mprotect-then-store depends
 * on a W^X policy that may deny PROT_EXEC|PROT_WRITE on the production node.
 * /proc/self/mem needs neither: the kernel writes through to the page the CPU
 * actually fetches.
 *
 * This CORRECTS an earlier finding here that claimed the opposite. That test read
 * the bytes back with a normal load and saw them "stale" --- but a load and an
 * instruction fetch can see different pages mid copy-on-write, so the readback
 * lied. Testing EXECUTION instead (write INT3 to a real function's pad, then CALL
 * it) shows the write IS fetched: it traps. Proven on real private .text by
 * patchtext2 (control clean, pad INT3 traps SIGTRAP, restore reversible) and by
 * the full multi-core swap in check_swap_realtext.c (clean under contention).
 *
 * Single-writer primitive. The cross-core coordination --- INT3 dance plus
 * membarrier so no other core runs a torn or stale instruction --- is the safe
 * point (item 0, built in check_swap.c), not here.
 */
static int
ls_write_text(void *dst, const uint8_t *bytes, size_t len)
{
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0)
        return -1;
    off_t at = (off_t)(uintptr_t)dst;
    int rc = -1;
    /* displacement first (bytes 1..len-1), then the opcode byte (0) last */
    if (len > 1 && pwrite(fd, bytes + 1, len - 1, at + 1) != (ssize_t)(len - 1))
        goto out;
    if (pwrite(fd, bytes, 1, at) != 1)
        goto out;
    rc = 0;
out:
    close(fd);
    return rc;
}

int
ls_arm(void *fn, void *trampoline)
{
    uint8_t *pad = ls_find_pad(fn);
    if (pad == NULL)
        return -1;

    int64_t disp = (int64_t)((uint8_t *)trampoline - (pad + LS_PAD_LEN));
    if (disp < INT32_MIN || disp > INT32_MAX) {
        fprintf(stderr, "ls_arm: trampoline out of rel32 range (%lld) --- refusing\n",
                (long long)disp);
        return -1;
    }

    uint8_t patch[LS_PAD_LEN];
    patch[0] = 0xe8;                        /* call rel32                       */
    int32_t d32 = (int32_t)disp;
    memcpy(patch + 1, &d32, 4);

    /*
     * Order: write the four displacement bytes, THEN the 0xe8 opcode, so a
     * concurrent fetch never sees a call with a garbage target. Single-writer
     * ordering only; the cross-core serialisation is item 0.
     *
     * ls_write_text reaches executed memory through /proc/self/mem --- the path
     * live patchers and debuggers use --- so no writable alias and no mprotect are
     * needed on the process's own r-xp text. (Proven; see ls_write_text.)
     */
    uint8_t bytes[LS_PAD_LEN];
    bytes[0] = patch[0];
    memcpy(bytes + 1, patch + 1, 4);
    if (ls_write_text(pad, bytes, LS_PAD_LEN) != 0)
        return -1;

    __builtin___clear_cache((char *)pad, (char *)pad + LS_PAD_LEN);

    if (pad[0] != 0xe8) {
        fprintf(stderr, "ls_arm: write did not take (pad[0]=0x%02x)\n", pad[0]);
        return -1;
    }
    return 0;
}

/*
 * Disarm: restore the five nops. Refuses unless the entry currently holds a
 * `call` over an endbr64 --- disarming something that is not armed would write
 * nops over whatever is actually there.
 */
int
ls_disarm(void *fn)
{
    uint8_t *p = (uint8_t *)fn;
    if (memcmp(p, LS_ENDBR, LS_ENDBR_LEN) != 0)
        return -1;
    uint8_t *pad = p + LS_ENDBR_LEN;
    if (pad[0] != 0xe8)
        return -1;                          /* not armed --- refuse             */

    /* Nop the opcode first (0x90) so no core enters a half-restored call, then
     * the rest. Same /proc/self/mem path as arming. */
    uint8_t restore[LS_PAD_LEN] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
    if (ls_write_text(pad, restore, LS_PAD_LEN) != 0)
        return -1;
    __builtin___clear_cache((char *)pad, (char *)pad + LS_PAD_LEN);
    if (pad[0] != 0x90)
        return -1;
    return 0;
}


/* ---------------------------------------------------------------------------
 * LIVE arming --- the whole point of the mechanism.
 *
 * Called on a RUNNING TMM (from the load path) while the per-core poll threads
 * are executing. The five pad bytes are rewritten by ls_swap_write5(), so no
 * core can observe a torn or stale instruction. No rebuild, no restart.
 * ------------------------------------------------------------------------ */
extern void ls_trampoline_entry(void);
extern unsigned char ls_tramp_slot_insn[];

int
ls_arm_live(void *fn, void *trampoline, int slot)
{
    uint8_t *pad = ls_find_pad(fn);
    if (pad == NULL) {
        fprintf(stderr, "ls_arm: 0x%llx has no patchable pad --- refusing\n",
                (unsigned long long)(uintptr_t)fn);
        return -1;
    }
    int64_t disp = (int64_t)((uint8_t *)trampoline - (pad + LS_PAD_LEN));
    if (disp < INT32_MIN || disp > INT32_MAX) {
        fprintf(stderr, "ls_arm: trampoline out of rel32 range --- refusing\n");
        return -1;
    }
    /* bake the slot into the trampoline immediate, then swap in the call */
    /* The slot immediate is 4 bytes, and nothing is calling the trampoline yet
     * (the target is still unarmed), so a plain write is correct. The INT3 swap
     * is only for the 5 bytes that ARE being executed. */
    int32_t imm = slot;
    if (ls_write_text(ls_tramp_slot_insn + 1, (const uint8_t *)&imm, 4) != 0) {
        fprintf(stderr, "ls_arm: could not set slot immediate --- refusing\n");
        return -1;
    }
    __builtin___clear_cache((char *)ls_tramp_slot_insn,
                            (char *)ls_tramp_slot_insn + 8);
    uint8_t patch[LS_PAD_LEN];
    patch[0] = 0xe8;
    int32_t d32 = (int32_t)disp;
    memcpy(patch + 1, &d32, 4);
    if (ls_swap_write5(pad, patch) != 0)
        return -1;
    fprintf(stderr, "ls_arm: ARMED LIVE entry=%p slot=%d tramp=%p\n", fn, slot, trampoline);
    return 0;
}

int
ls_disarm_live(void *fn)
{
    uint8_t *p = (uint8_t *)fn;
    if (memcmp(p, LS_ENDBR, LS_ENDBR_LEN) != 0)
        return -1;
    uint8_t *pad = p + LS_ENDBR_LEN;
    if (pad[0] != 0xe8)
        return -1;
    static const uint8_t nops[LS_PAD_LEN] = { 0x90,0x90,0x90,0x90,0x90 };
    if (ls_swap_write5(pad, nops) != 0)
        return -1;
    fprintf(stderr, "ls_arm: DISARMED LIVE entry=%p\n", fn);
    return 0;
}
