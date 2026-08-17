/* ls_frida_probe.c --- does Frida-gum work INSIDE TMM, on a real unpadded function?
 *
 * THE EXPERIMENT, AND WHY A HARNESS COULD NOT SETTLE IT. A standalone TMM-shaped
 * process (env/experiments/frida-tmm-shape.c) already showed Frida inline-hooking an
 * unpadded function under 8-thread load: 10M calls, zero corrupted results, entry
 * bytes restored on detach. That killed the unevidenced claim in widening-plan.md
 * that Frida "collides with TMM's memory layout".
 *
 * But a shaped harness cannot test the parts that actually carry the risk:
 *
 *   - TMM ALIASES malloc to a per-core allocator whose spinlock is never spin_init'd
 *     on threads TMM did not create. Frida allocates. We have already lost a day to
 *     exactly this failure with our own loader thread.
 *   - Frida places its trampolines near the target; `call/jmp rel32` spans +/-2GB and
 *     TMM's .text sits inside a ~200MB binary. Probably fine, never checked.
 *   - Relocation safety depends on WHICH instructions get displaced. The harness
 *     tested ONE function whose entry was endbr64/mov/lea --- trivially relocatable.
 *     TMM has ~74,000 functions and the dangerous ones are those with a branch target
 *     inside the first five bytes.
 *   - PGO'd entry sequences differ from -O2.
 *
 * So this runs in TMM proper. It is OFF unless LS_FRIDA_TARGET names an address, and
 * it does nothing but count --- no verdict, no data-plane effect, no interaction with
 * the pad-based path.
 *
 * WHAT A PASS WOULD MEAN. If Frida hooks an UNPADDED function inside a live TMM, then
 * bpftime plausibly solves the CVE reachability problem that pad-based arming
 * structurally cannot: outside the TMM core nothing is padded, which is why OpenSSL's
 * 1,781 linked symbols are unreachable whatever CVE exists in them. That would make
 * "keep hand-building" the wrong call, and it is better to find that out from an
 * experiment than from a reviewer.
 *
 * WHAT A FAILURE WOULD MEAN. The pad approach is vindicated on evidence rather than
 * on an assertion I made up, and hardware watchpoints stay the CVE path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frida-gum.h"

#include "ls_frida_probe.h"

/* Counted, not logged per hit: this may sit on a per-request path and a printf there
 * would measure the printf. */
static volatile unsigned long long g_frida_hits;
static int g_frida_on;

static void
ls_frida_on_enter(GumInvocationContext *ic, gpointer user_data)
{
    (void)ic; (void)user_data;
    g_frida_hits++;
}

static void
ls_frida_on_leave(GumInvocationContext *ic, gpointer user_data)
{
    (void)ic; (void)user_data;
}

/*
 * Called from ls_vm.c's init, on the thread TMM starts us on.
 *
 * LS_FRIDA_TARGET is an ADDRESS in hex, not a symbol name: the shipped binary is
 * stripped, so gum_module_find_export_by_name would fail for anything that is not a
 * dynamic export --- and the interesting targets (statics, OpenSSL internals) never
 * are. The address comes from the same place arming addresses come from: nm on the
 * matching debuginfo, via bnk-preflight.sh.
 */
void
ls_frida_probe_init(void)
{
    const char *t = getenv("LS_FRIDA_TARGET");
    unsigned long long addr;
    GumInterceptor *interceptor;
    GumInvocationListener *listener;
    int rc;

    if (t == NULL || *t == '\0')
        return;                       /* off by default --- this is an experiment */

    addr = strtoull(t, NULL, 0);
    if (addr == 0) {
        fprintf(stderr, "ls_frida: LS_FRIDA_TARGET=%s is not an address\n", t);
        return;
    }

    fprintf(stderr, "ls_frida: EXPERIMENT --- attaching frida-gum to 0x%llx\n", addr);

    /* The first real gate. gum_init_embedded() allocates and starts glib's machinery
     * inside a process whose malloc is TMM's per-core allocator. If Frida is going to
     * be incompatible with TMM, the most likely place is right here, and a hang is as
     * informative as a crash. */
    gum_init_embedded();
    fprintf(stderr, "ls_frida: gum_init_embedded() returned\n");

    interceptor = gum_interceptor_obtain();
    if (interceptor == NULL) {
        fprintf(stderr, "ls_frida: no interceptor --- giving up\n");
        return;
    }

    listener = gum_make_call_listener(ls_frida_on_enter, ls_frida_on_leave, NULL, NULL);

    gum_interceptor_begin_transaction(interceptor);
    rc = gum_interceptor_attach(interceptor, (gpointer)(uintptr_t)addr, listener, NULL);
    gum_interceptor_end_transaction(interceptor);

    fprintf(stderr, "ls_frida: attach(0x%llx) -> %d %s\n", addr, rc,
            rc == GUM_ATTACH_OK ? "OK" : "REFUSED");

    if (rc == GUM_ATTACH_OK) {
        const unsigned char *p = (const unsigned char *)(uintptr_t)addr;
        fprintf(stderr, "ls_frida: entry now %02x %02x %02x %02x %02x\n",
                p[0], p[1], p[2], p[3], p[4]);
        g_frida_on = 1;
    }
}

/* Read by the loader's STATUS path so hits are observable without a per-hit log. */
unsigned long long
ls_frida_hits(void)
{
    return g_frida_on ? g_frida_hits : 0ull;
}
