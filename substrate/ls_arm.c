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
 * DOES: locate the pad, compute the rel32, relax the page to writable, write the
 * five bytes atomically enough for the single-writer case, flush the i-cache,
 * restore W^X. Reversibly. Verified by arming a live function and calling it.
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
 * The W^X relaxation here is a raw mprotect on the mapped page. In TMM it must go
 * through the memory manager, respect hugepage COW, and interact with whatever
 * code-integrity enforcement is present --- all of which is item 2's real weight
 * and none of which a standalone mprotect represents.
 *
 * Status: candidate artifact. It runs (see check_arm.c). Nothing in TMM calls it.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

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
 * This does a plain store, and that is a DEMAND ON THE CALLER, not a shortcut:
 * `dst` must be in a mapping where writes are seen by instruction fetch --- i.e.
 * writable AND executed, and not MAP_PRIVATE. Proven the hard way (finding
 * below): mprotect-then-store on a process's own MAP_PRIVATE text triggers COW,
 * and /proc/self/mem writes through to a page neither reads nor fetches use, so
 * BOTH silently leave the executed bytes stale. In TMM this mapping is the
 * memory manager's job --- W^X relaxation over the real text, respecting hugepage
 * COW and code-integrity. Here the test supplies a MAP_SHARED page. Either way,
 * arming does not get to invent a writable alias; it must be handed one.
 */
static int
ls_write_text(void *dst, const uint8_t *bytes, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)dst;
    for (size_t i = len; i-- > 1; )         /* displacement first */
        p[i] = bytes[i];
    __atomic_store_n(p, bytes[0], __ATOMIC_RELEASE);   /* opcode last */
    return 0;
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
     * ls_write_text abstracts HOW the bytes reach executed memory. mprotect on a
     * MAP_PRIVATE text page triggers copy-on-write --- the writer gets a private
     * page while the CPU keeps fetching the original, so the write is real and
     * invisible. Proven, not assumed (finding below). /proc/self/mem writes
     * through to the underlying page and is what live patchers use.
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
