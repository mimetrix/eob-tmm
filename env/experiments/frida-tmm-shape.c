/*
 * frida-tmm-shape.c --- can Frida-gum inline-hook a function in a TMM-shaped process,
 * while other threads are executing that function?
 *
 * WHY THIS EXPERIMENT EXISTS. widening-plan.md asserts that adopting bpftime "means
 * Frida-gum ... inside TMM's data plane [and] Frida installs its own inline
 * trampolines, which collides with pad-based arming and with TMM's memory layout". I
 * wrote that assertion and had no evidence for it. It is load-bearing: if Frida works
 * here, bpftime plausibly solves BOTH exit probes AND the CVE reachability problem ---
 * because inline hooking needs no compiler pad --- and continuing to hand-build is the
 * wrong call. If it does not work, the pad approach is vindicated on evidence.
 *
 * FOUR QUESTIONS, each with a pass/fail the program decides for itself:
 *
 *   Q1 REACH      Can it hook a function with NO patchable-entry pad? This is the one
 *                 that matters most --- the pad requirement is why OpenSSL's 1,781
 *                 linked symbols are unreachable, and it is the whole CVE blocker.
 *   Q2 LIVE       Can the hook be installed while N threads are inside/calling the
 *                 target? Our claim is arming a RUNNING data plane; a mechanism that
 *                 needs quiescence is a different product.
 *   Q3 CORRECT    Does the target keep returning correct results across the patch?
 *                 Inline hooking relocates displaced instructions; if a branch target
 *                 lands inside the moved range, results corrupt rather than crash.
 *   Q4 RESTORE    Does detach put things back, with the hammer threads still running?
 *
 * TMM-SHAPED means: statically linked, -no-pie, threads that run to completion in
 * tight loops, and a target function the compiler did NOT pad. The harness verifies
 * the "not padded" part rather than assuming it.
 *
 * WHAT THIS DOES NOT TEST, so nobody over-reads the result: TMM's own allocator, its
 * signal disposition, its memory layout at 200MB of .text, or PGO'd code. A pass here
 * is necessary, not sufficient.
 */
#include "frida-gum.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HAMMER_THREADS 8

static atomic_ullong g_calls;        /* how many times the target really ran     */
static atomic_ullong g_wrong;        /* results that came back corrupted          */
static atomic_int    g_stop;
static atomic_ullong g_hook_hits;    /* how many times Frida's listener fired     */

/*
 * The target. Deliberately NOT marked noinline-with-a-pad: this file is compiled
 * without -fpatchable-function-entry, so the entry is whatever gcc emits --- which is
 * the situation for every function outside the TMM core.
 *
 * It computes something checkable. If inline hooking relocates a displaced instruction
 * incorrectly, or a jump target lands inside the moved bytes, the arithmetic breaks
 * and g_wrong climbs --- which is a far more useful failure than a segfault, because it
 * is the SILENT one.
 */
__attribute__((noinline))
static unsigned long
hot_target(unsigned long a, unsigned long b)
{
    unsigned long acc = a ^ 0x5a5a5a5aUL;
    int i;

    for (i = 0; i < 4; i++)
        acc = (acc << 1) ^ (acc >> 3) ^ (b + (unsigned long)i);

    atomic_fetch_add(&g_calls, 1);
    return acc;
}

/* Computed the same way, without the hook, so the hammer can check its own results. */
static unsigned long
hot_target_ref(unsigned long a, unsigned long b)
{
    unsigned long acc = a ^ 0x5a5a5a5aUL;
    int i;
    for (i = 0; i < 4; i++)
        acc = (acc << 1) ^ (acc >> 3) ^ (b + (unsigned long)i);
    return acc;
}

static void *
hammer(void *arg)
{
    unsigned long seed = (unsigned long)(uintptr_t)arg;

    while (!atomic_load(&g_stop)) {
        unsigned long a = seed++, b = seed * 3u;
        if (hot_target(a, b) != hot_target_ref(a, b))
            atomic_fetch_add(&g_wrong, 1);
    }
    return NULL;
}

static void
on_enter(GumInvocationContext *ic, gpointer user_data)
{
    (void)ic; (void)user_data;
    atomic_fetch_add(&g_hook_hits, 1);
}

static void
on_leave(GumInvocationContext *ic, gpointer user_data)
{
    (void)ic; (void)user_data;
}

/* Report the first bytes of the target so the "no pad" claim is shown, not asserted.
 * A padded entry is endbr64 (f3 0f 1e fa) + 5 x 0x90, or 5 x 0x90 at +0. */
static void
dump_entry(const char *label, const unsigned char *p)
{
    int i;
    printf("  %-22s", label);
    for (i = 0; i < 12; i++)
        printf(" %02x", p[i]);
    if (p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfa &&
        p[4] == 0x90 && p[5] == 0x90 && p[6] == 0x90 && p[7] == 0x90 && p[8] == 0x90)
        printf("   <- PADDED (endbr64 + 5 nops)");
    else if (p[0] == 0x90 && p[1] == 0x90 && p[2] == 0x90 && p[3] == 0x90 && p[4] == 0x90)
        printf("   <- PADDED (5 nops at +0)");
    else
        printf("   <- NOT padded");
    printf("\n");
}

int
main(void)
{
    GumInterceptor *interceptor;
    GumInvocationListener *listener;
    pthread_t th[HAMMER_THREADS];
    unsigned long long calls_before, hits_after, wrong_total;
    unsigned char entry_before[16], entry_after[16], entry_restored[16];
    int i, rc = 0;

    printf("=== Frida-gum in a TMM-shaped process ===\n");
    /* No gum_version_string() in this devkit; the tarball name carries the version
     * and printing a bogus %s from an implicitly-declared int would segfault before
     * the experiment ran. */
    printf("  %d hammer threads, static + no-pie\n\n", HAMMER_THREADS);

    memcpy(entry_before, (void *)hot_target, sizeof entry_before);
    dump_entry("target entry, before", entry_before);

    /* Q1's precondition: if this were padded the experiment would prove nothing. */
    if ((entry_before[0] == 0xf3 && entry_before[4] == 0x90) || entry_before[0] == 0x90) {
        printf("\n*** target IS padded --- rebuild without -fpatchable-function-entry\n");
        return 2;
    }

    gum_init_embedded();
    interceptor = gum_interceptor_obtain();
    listener = gum_make_call_listener(on_enter, on_leave, NULL, NULL);

    /* --- Q2: start the hammer FIRST, then patch underneath it ------------------ */
    for (i = 0; i < HAMMER_THREADS; i++)
        pthread_create(&th[i], NULL, hammer, (void *)(uintptr_t)(i + 1));

    usleep(200000);                       /* let them get well into the loop */
    calls_before = atomic_load(&g_calls);
    printf("\n  hammer running: %llu calls before attach\n", calls_before);
    if (calls_before == 0) {
        printf("*** hammer never ran --- experiment invalid\n");
        return 2;
    }

    printf("  attaching WHILE %d threads execute the target...\n", HAMMER_THREADS);
    gum_interceptor_begin_transaction(interceptor);
    rc = gum_interceptor_attach(interceptor, (gpointer)hot_target, listener, NULL);
    gum_interceptor_end_transaction(interceptor);
    printf("  gum_interceptor_attach -> %d (%s)\n", rc,
           rc == GUM_ATTACH_OK ? "OK" : "REFUSED");

    memcpy(entry_after, (void *)hot_target, sizeof entry_after);
    dump_entry("target entry, hooked", entry_after);

    usleep(400000);                       /* run hooked, under load */
    hits_after = atomic_load(&g_hook_hits);
    printf("\n  listener fired %llu times while hooked\n", hits_after);

    /* --- Q4: detach, still under load ----------------------------------------- */
    printf("  detaching WHILE the threads still run...\n");
    gum_interceptor_detach(interceptor, listener);
    memcpy(entry_restored, (void *)hot_target, sizeof entry_restored);
    dump_entry("target entry, detached", entry_restored);

    usleep(200000);
    atomic_store(&g_stop, 1);
    for (i = 0; i < HAMMER_THREADS; i++)
        pthread_join(th[i], NULL);

    wrong_total = atomic_load(&g_wrong);

    printf("\n=== results ===\n");
    printf("  Q1 REACH    hook an UNPADDED function      : %s\n",
           rc == GUM_ATTACH_OK ? "PASS" : "FAIL");
    printf("  Q2 LIVE     attach under %d-thread load     : %s\n", HAMMER_THREADS,
           (rc == GUM_ATTACH_OK && hits_after > 0) ? "PASS" : "FAIL");
    printf("  Q3 CORRECT  no corrupted results           : %s  (%llu wrong of %llu)\n",
           wrong_total == 0 ? "PASS" : "FAIL",
           wrong_total, (unsigned long long)atomic_load(&g_calls));
    printf("  Q4 RESTORE  entry bytes restored on detach : %s\n",
           memcmp(entry_before, entry_restored, sizeof entry_before) == 0
               ? "PASS" : "FAIL (bytes differ)");
    printf("\n  total calls %llu, listener hits %llu\n",
           (unsigned long long)atomic_load(&g_calls), hits_after);

    g_object_unref(listener);
    g_object_unref(interceptor);
    gum_deinit_embedded();

    return (rc == GUM_ATTACH_OK && wrong_total == 0 && hits_after > 0) ? 0 : 1;
}
