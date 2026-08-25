/* bench_tramp.c --- the per-invocation data-path cost of an armed hook, definitively.
 *
 * THE QUESTION THIS ANSWERS, and why the shipped counters cannot. The `cycles` counter
 * in ls_vm.c times the PROGRAM (an rdtsc pair inside ls_vm_call). It does not time the
 * trampoline: the `call rel32` over the pad, the ten register pushes, the ctx setup, the
 * dispatch, and the ten pops on the way out. That machinery is the data-path cost, and it
 * is the number that decides whether this is a data-plane mechanism or an expensive uprobe.
 *
 * HOW. victim() carries the exact 5-byte patch arming produces and routes through the REAL
 * trampoline (trampoline_x86_64.S). victim_unarmed() is byte-for-byte the same function with
 * the pad left as nops. Timing both in a tight loop and taking the DELTA isolates the
 * trampoline: everything else --- the call frame, the body, the loop --- is identical and cancels.
 *
 * PREEMPTION. A single rdtsc pair spanning a context switch measures the scheduler, not the
 * code (this repo has been bitten by exactly that). So: many batches, report the MIN batch ---
 * the one least disturbed --- and pin to one CPU. The min is the honest floor; mean and max carry
 * preemption and are printed only for contrast.
 *
 * LADDER. Three rungs so the trampoline cost is separated from program cost:
 *   unarmed         the padded function, not armed
 *   armed, empty    trampoline runs, ls_vm_call returns FALLTHROUGH immediately  (MECHANISM floor)
 *   armed, work     ls_vm_call does a small real computation                     (observe-mode-ish)
 */
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#define LS_FALLTHROUGH 0
#define LS_SAFE_RETURN 1

extern uint64_t victim(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t victim_unarmed(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t body_ran, body_ran2;

/* The dispatch target the trampoline calls. A switch picks how much work it does, so the
 * SAME trampoline path is measured with an empty program and with a small real one. */
static volatile int g_mode;     /* 0 = empty, 1 = small work */
static volatile uint64_t g_sink;
static uint64_t g_fired;

/* The two symbols ls_tramp_dispatch references besides ls_vm_call. Stubbed to the
 * CHEAPEST REAL PATH an untyped probe takes: no typed ctx builder (returns NULL), so the
 * dispatch builds the generic five-slot ctx and calls ls_vm_call --- exactly what arming an
 * arbitrary function with a generic probe does live. ls_tp_dispatch is defined for linking
 * and is never reached on this path (it fires only for a typed builder with a ring id). */
const void *ls_vm_ctx_reg(int slot) { (void)slot; return 0; }
int ls_tp_dispatch(int slot, void *out, unsigned long n, unsigned int hid)
{ (void)slot;(void)out;(void)n;(void)hid; return LS_FALLTHROUGH; }

int ls_vm_call(int slot, void *ctx, size_t n)
{
    (void)slot;
    g_fired++;
    if (g_mode) {
        /* a few dependent ops over the ctx --- stands in for an observe program that reads
         * a field and compares it, without pulling the whole ubpf JIT into a microbench */
        const uint64_t *a = (const uint64_t *)ctx;
        uint64_t h = 0;
        for (size_t i = 0; i < n/8 && i < 6; i++) h = h*1099511628211ull ^ a[i];
        g_sink += h;
    }
    return LS_FALLTHROUGH;      /* observe: fall through, body runs --- same as unarmed path */
}

static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ __volatile__("lfence; rdtsc" : "=a"(lo), "=d"(hi));   /* lfence: serialize */
    return ((uint64_t)hi << 32) | lo;
}

/* min cycles-per-call of `fn`, over B batches of N, pinned, preemption rejected by min. */
static double bench(uint64_t (*fn)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t),
                    long N, int B, double *mean_out, uint64_t *max_out)
{
    uint64_t best = ~0ull, sum = 0, worst = 0;
    for (int b = 0; b < B; b++) {
        uint64_t t0 = rdtsc();
        for (long i = 0; i < N; i++) g_sink += fn(0xA1,0xB2,0xC3,0xD4,0xE5);
        uint64_t d = rdtsc() - t0;
        if (d < best) best = d;
        if (d > worst) worst = d;
        sum += d;
    }
    *mean_out = (double)sum / B / N;
    *max_out  = worst / N;
    return (double)best / N;
}

int main(int argc, char **argv)
{
    long N = (argc > 1) ? atol(argv[1]) : 2000000;
    int  B = (argc > 2) ? atoi(argv[2]) : 400;
    double GHZ = (argc > 3) ? atof(argv[3]) : 2.6;
    double mean; uint64_t mx;

    /* warm i-cache / branch predictors */
    for (int i = 0; i < 100000; i++) { g_sink += victim_unarmed(1,2,3,4,5); g_sink += victim(1,2,3,4,5); }

    double c_unarmed = bench(victim_unarmed, N, B, &mean, &mx);
    double m_unarmed = mean;

    g_mode = 0;
    double c_empty = bench(victim, N, B, &mean, &mx);
    double m_empty = mean;

    g_mode = 1;
    double c_work = bench(victim, N, B, &mean, &mx);
    double m_work = mean;

    printf("  N=%ld iterations x B=%d batches, min-of-batches, pinned; %.2f GHz\n\n", N, B, GHZ);
    printf("  %-26s %10s %10s   %10s\n", "path", "cyc/call", "ns/call", "mean cyc");
    printf("  %-26s %10.2f %10.3f   %10.2f\n", "unarmed (padded fn)", c_unarmed, c_unarmed/GHZ, m_unarmed);
    printf("  %-26s %10.2f %10.3f   %10.2f\n", "armed, empty program", c_empty, c_empty/GHZ, m_empty);
    printf("  %-26s %10.2f %10.3f   %10.2f\n", "armed, small program", c_work, c_work/GHZ, m_work);
    printf("\n  DATA-PATH COST OF THE TRAMPOLINE (armed-empty minus unarmed):\n");
    printf("    %.2f cycles  =  %.3f ns per invocation\n", c_empty - c_unarmed, (c_empty - c_unarmed)/GHZ);
    printf("  With a small observe program on top:\n");
    printf("    %.2f cycles  =  %.3f ns per invocation\n", c_work - c_unarmed, (c_work - c_unarmed)/GHZ);
    printf("\n  fired=%llu  sink=%llu  body_ran=%llu/%llu (nonzero => body executed on fall-through)\n",
        (unsigned long long)g_fired, (unsigned long long)g_sink,
        (unsigned long long)body_ran, (unsigned long long)body_ran2);
    return 0;
}
