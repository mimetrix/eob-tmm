/*
 * pad-tax.c --- what does -fpatchable-function-entry actually COST at runtime?
 *
 * The flag reserves 5 bytes at every function entry so a hook can be written there
 * later. Those bytes are five 0x90 nops, and they EXECUTE on every call to every
 * padded function, forever, armed or not. Deciding whether to pad more of TMM means
 * knowing that number rather than assuming it is negligible.
 *
 * Compiled TWICE from this one file --- once with the flag, once without --- and the
 * difference is the tax. Everything else is identical, so nothing else can explain a
 * gap.
 *
 * WHAT IS MEASURED. A leaf function called in a tight loop. That is the WORST case for
 * the flag and the best case for measuring it: call overhead is the whole body, so the
 * nops are maximally visible. A function that does real work amortises them.
 *
 * WHAT IS NOT MEASURED, so the number is not over-read:
 *   - I-cache pressure. 5 extra bytes per entry across ~80,000 functions is ~400KB of
 *     additional instruction footprint. A microbenchmark with one hot function has a
 *     tiny working set and cannot see this. It may well dominate the nop cost in a real
 *     data plane, and measuring it needs a realistic working set.
 *   - Any effect the flag has on inlining or alignment decisions.
 *   - PGO builds, which TMM also produces.
 *
 * So this establishes a FLOOR on the per-call cost, not the total cost.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ITERS   200000000ull
#define REPEATS 5

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* noinline, or the compiler deletes the call and there is no entry to pad. volatile
 * accumulator so the loop cannot be hoisted. */
__attribute__((noinline)) static uint64_t leaf(uint64_t x) { return x + 1; }

int main(void)
{
    const unsigned char *p = (const unsigned char *)leaf;
    volatile uint64_t sink = 0;
    uint64_t best = ~0ull;
    int r;

    printf("  entry bytes :");
    for (int i = 0; i < 10; i++) printf(" %02x", p[i]);
    /* Report what the compiler actually emitted --- claiming "with the flag" without
     * checking is how a null result gets mistaken for a cheap one. */
    if (p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfa &&
        !memcmp(p + 4, "\x90\x90\x90\x90\x90", 5))
        printf("   PADDED (endbr64 + 5 nops)\n");
    else if (!memcmp(p, "\x90\x90\x90\x90\x90", 5))
        printf("   PADDED (5 nops at +0)\n");
    else
        printf("   NOT padded\n");

    /* Best-of-N, not the mean: this is a cycle count on a preemptible thread, and a
     * scheduler tick inside the window inflates the mean without bound. The minimum
     * is the run that was not interrupted. */
    for (r = 0; r < REPEATS; r++) {
        uint64_t t0 = rdtsc(), acc = 0;
        for (uint64_t i = 0; i < ITERS; i++) acc = leaf(acc);
        uint64_t d = rdtsc() - t0;
        sink = acc;
        if (d < best) best = d;
    }
    (void)sink;

    printf("  %llu calls, best of %d: %llu cycles  =  %.4f cycles/call\n",
           ITERS, REPEATS, (unsigned long long)best, (double)best / (double)ITERS);
    return 0;
}
