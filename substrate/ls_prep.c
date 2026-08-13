/*
 * ls_prep.c --- run shield preparation on a TMM thread.
 *
 * Compiled in TMM's include world (no STDINC in src/compile/filelist), because
 * the periodic timer and `tid` live there. Everything else about the handoff ---
 * the request state, the work, the loader-side wait --- is in ls_vm_load.c,
 * which is STDINC and stays portable. The only things crossing that line are two
 * function symbols; no struct and no type does.
 *
 * WHY THIS FILE EXISTS. ubpf_create/ubpf_load_elf/ubpf_compile all allocate, and
 * allocation on a thread we created never returns: TMM aliases malloc to its own
 * allocator (kern/malloc.c:48), which for a foreign thread reaches
 * init_thread_cache() -> spin_lock() on a lock nothing ever spin_init'd, because
 * sthread_handler_register() is called from exactly one site in the tree
 * (dev/ndal/xnet/if_xnet.c:1642) and BNK does not load xnet. Measured: the
 * loader thread goes on-CPU and never comes back.
 *
 * A PERIODIC TIMER, NOT A ONE-SHOT. Adding a timer from the loader thread would
 * race the callwheel the poll loop is walking. This one is registered once, at
 * startup, from a TMM thread; afterwards the loader only ever stores to a word.
 * No cross-thread insertion happens at all.
 *
 * OWNERSHIP. http_psm_init() runs once per TMM thread (http_init guards with
 * static RTTHREAD BOOL http_inited, http.c:2529), so every TMM thread reaches
 * ls_vm_loader_start() and therefore this. tid 0 takes it --- the same election
 * tm_lib/urlcat/dpi_url_lookup.c:400 uses for its mmap writer.
 *
 * IDLE COST. One relaxed atomic load per tick, on one thread.
 */
/* Include set mirrors tm_lib/urlcat/dpi_url_lookup.c, the existing user of this
 * timer API --- local/sys/timer.h needs queue.h for LIST_ENTRY and time.h for
 * tmm_clock_get_ticks, and neither is self-included. */
#include <local/sys/types.h>
#include <local/sys/bitset.h>
#include <local/sys/cpu.h>
#include <local/sys/def.h>
#include <local/sys/err.h>
#include <local/sys/debug.h>
#include <local/sys/lib.h>
#include <local/sys/queue.h>
#include <local/sys/thread.h>
#include <local/sys/spin.h>
#include <local/kern/sys.h>
#include <local/sys/time.h>
#include <local/sys/timer_external.h>
#include <local/sys/init.h>

/* In ls_vm_load.c. void(void) on purpose: no TMM type may cross into that file,
 * and no STDINC type may cross into this one. */
extern void ls_prep_run_pending(void);
extern int  ls_prep_timer_on;

void ls_prep_timer_start(void);

/* Loads are rare and a human is waiting on the reply, so this trades a little
 * latency for a negligible idle cost. */
#define LS_PREP_TICKS (TICKS_PER_SEC / 100 ? TICKS_PER_SEC / 100 : 1)

static struct timer_periodic ls_prep_timer;

static void
ls_prep_timer_cb(struct timer *timer, void *arg)
{
    (void)timer;
    (void)arg;
    ls_prep_run_pending();
}

void
ls_prep_timer_start(void)
{
    if (tid != 0 || ls_prep_timer_on)
        return;
    timer_add_periodic_ex(&ls_prep_timer, ls_prep_timer_cb, NULL, LS_PREP_TICKS);
    ls_prep_timer_on = 1;
    /* printf, not fprintf: this file is built -nostdinc and TMM provides its
     * own printf (see kern/sthread_memory.c for the same usage). */
    printf("ls_vm: prepare handoff armed on tmm %d (every %d ticks)\n",
           (int)tid, (int)LS_PREP_TICKS);
}

/*
 * Startup registration --- this is why no F5 source file calls into the VM.
 *
 * INIT_FUNC registers into TMM's init linker set (local/sys/init.h), the same
 * mechanism urlcat, pem_lib and license_pgo_gen use. INIT_LATE (-10) is in the
 * "events in threads" group, so this runs once per TMM thread with `tid` valid
 * --- exactly where the bootstrap used to sit inside http_psm_init(), which is
 * what the tid-0 timer election and the per-thread VM state expect.
 *
 * The work itself is ls_vm_bootstrap() in ls_vm_load.c. Only a void(void)
 * crosses the include-world boundary; see the note on that function for why.
 */
extern void ls_vm_bootstrap(void);

static err_t
ls_startup(void)
{
    ls_vm_bootstrap();
    return ERR_OK;
}

INIT_FUNC(INIT_LATE, ls_startup);
