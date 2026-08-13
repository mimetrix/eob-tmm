/* check_swap_realtext.c --- the safe swap, on the REAL surface.
 *
 * check_swap.c proved the text_poke_bp protocol race-safe, but on a scratch page
 * we allocated MAP_SHARED and wrote with plain stores. TMM's functions are not
 * that: they live in the binary's own .text, mapped r-xp (private), and the only
 * way to write them is the path gdb uses for breakpoints --- /proc/self/mem ---
 * which we just proved reaches the *executed* bytes (patchtext2: control clean,
 * INT3 at the pad traps SIGTRAP, restore reversible).
 *
 * This joins the two: run the full text_poke_bp arm/disarm dance, under multi-core
 * contention, against a REAL compiled function's -fpatchable-function-entry pad,
 * with every patch byte written through /proc/self/mem. A store and a pwrite have
 * different latency and visibility, so the protocol's race-safety must be re-proven
 * on this write path, not assumed.
 *
 * Target: swap_target(), a real function; its pad is endbr64 + 5 nops (verified in
 * patchtext2). Trampoline: the same validated test_tramp stub. Both are ordinary
 * symbols in this binary's .text, so they are trivially within rel32 --- no mmap
 * hint games. Legal worker returns: 103 (body) or 0 (safe-return); anything else,
 * or a fault, is the race caught.
 *
 * modes: 0 = UNSAFE opcode-first (teeth, via /proc/self/mem) ; 2 = text_poke_bp.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <linux/membarrier.h>

static void sync_cores(void)
{
    syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
}

extern void test_tramp(void);
extern volatile int g_tramp_hits, g_skip_body;

/* The real target. noinline+used so it survives as an out-of-line symbol with its
 * own pad; called only through g_target (a runtime pointer) so the compiler cannot
 * fold the constant into the caller. Body compiles to `mov $103,%eax; ret`. */
__attribute__((noinline,used))
static uint64_t swap_target(uint64_t a, uint64_t b) { (void)a; (void)b; return 103; }

typedef uint64_t (*fn2)(uint64_t,uint64_t);
static uint8_t *g_target;
static uint8_t *g_pad;                 /* the 5 patchable bytes: swap_target + 4 */
static int      g_memfd = -1;          /* /proc/self/mem --- the only writable view of .text */
static volatile int g_stop, g_widen, g_mode;
static _Atomic long g_faults, g_corrupt, g_calls, g_cycles, g_traps;

static __thread sigjmp_buf g_jb;
static __thread int g_in_call;

/* First-fault forensics: what signal, where did rip point, what address faulted,
 * all relative to the pad. Captured once (async-signal-safe: plain stores), printed
 * from the periodic loop. Tells us whether a fault is a fetch fault ON the pad (the
 * write perturbing a concurrent fetch) or something else entirely. */
static _Atomic int  g_fault_seen;
static volatile int g_fsig;
static volatile long g_frip_off, g_faddr_off;

/* Write into our own r-xp .text the way a live patcher does: through /proc/self/mem.
 * Single-byte writes are atomic; the 4-byte tail is only ever written while the
 * opcode slot holds a nop (mode 0) or an INT3 (mode 2), never while it is live. */
static void poke1(uint8_t *addr, uint8_t v)
{
    if (pwrite(g_memfd, &v, 1, (off_t)(uintptr_t)addr) != 1) { perror("poke1"); _exit(5); }
}
static void poke4(uint8_t *addr, const void *p)
{
    if (pwrite(g_memfd, p, 4, (off_t)(uintptr_t)addr) != 4) { perror("poke4"); _exit(5); }
}

static void
trap_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si;
    ucontext_t *c = (ucontext_t*)uc;
    uint8_t *rip = (uint8_t*)c->uc_mcontext.gregs[REG_RIP];
    if (rip == g_pad + 1) {                       /* trapped ON our INT3 */
        c->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)(g_pad + 5); /* -> body */
        __atomic_fetch_add(&g_traps, 1, __ATOMIC_RELAXED);
        return;
    }
    _exit(4);                                      /* INT3 anywhere else: bug */
}

static void
fault_handler(int sig, siginfo_t *si, void *uc)
{
    if (g_in_call) {
        if (!__atomic_exchange_n(&g_fault_seen, 1, __ATOMIC_RELAXED)) {
            ucontext_t *c = (ucontext_t*)uc;
            g_fsig = sig;
            g_frip_off  = (long)((uint8_t*)c->uc_mcontext.gregs[REG_RIP] - g_pad);
            g_faddr_off = (long)((uint8_t*)(si ? si->si_addr : 0) - g_pad);
        }
        __atomic_fetch_add(&g_faults, 1, __ATOMIC_RELAXED);
        siglongjmp(g_jb, 1);
    }
    _exit(2);
}

static void
do_arm(void)
{
    int32_t d = (int32_t)((uint8_t*)test_tramp - (g_pad + 5));
    if (g_mode == 0) {                             /* UNSAFE: opcode first, torn window */
        poke1(g_pad, 0xe8);
        for (volatile int z = 0; z < g_widen; z++) { }
        poke4(g_pad + 1, &d);
    } else {                                       /* text_poke_bp */
        poke1(g_pad, 0xcc);            sync_cores();
        for (volatile int z = 0; z < g_widen; z++) { }
        poke4(g_pad + 1, &d);         sync_cores();
        poke1(g_pad, 0xe8);           sync_cores();
    }
}

static void
do_disarm(void)
{
    static const uint8_t nops4[4] = { 0x90,0x90,0x90,0x90 };
    if (g_mode == 0) {
        poke1(g_pad, 0x90);
        poke4(g_pad + 1, nops4);
    } else {
        poke1(g_pad, 0xcc);           sync_cores();
        poke4(g_pad + 1, nops4);      sync_cores();
        poke1(g_pad, 0x90);           sync_cores();
    }
}

static void *
worker(void *arg)
{
    (void)arg;
    struct sigaction sa = {0};
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    fn2 f = (fn2)g_target;
    while (!g_stop) {
        if (sigsetjmp(g_jb, 1) == 0) {
            g_in_call = 1;
            uint64_t r = f(1, 2);
            g_in_call = 0;
            __atomic_fetch_add(&g_calls, 1, __ATOMIC_RELAXED);
            if (r != 103 && r != 0)
                __atomic_fetch_add(&g_corrupt, 1, __ATOMIC_RELAXED);
        } else {
            g_in_call = 0;
        }
    }
    return NULL;
}

static void *
armer(void *arg)
{
    (void)arg;
    while (!g_stop) {
        do_arm();
        do_disarm();
        __atomic_fetch_add(&g_cycles, 2, __ATOMIC_RELAXED);
    }
    return NULL;
}

int
main(int argc, char **argv)
{
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int nworkers = (argc > 1) ? atoi(argv[1]) : (ncpu > 2 ? ncpu - 1 : 1);
    int seconds  = (argc > 2) ? atoi(argv[2]) : 5;
    g_widen = (argc > 3) ? atoi(argv[3]) : 0;
    g_mode  = (argc > 4) ? atoi(argv[4]) : 2;

    g_target = (uint8_t*)swap_target;
    g_pad    = g_target + 4;                        /* after endbr64 */

    /* verify the target really carries the pad we assume (fail closed if not) */
    if (!(g_target[0]==0xf3 && g_target[1]==0x0f && g_target[2]==0x1e && g_target[3]==0xfa)) {
        printf("swap_target has no endbr64 (%02x %02x %02x %02x) --- rebuild with "
               "-fcf-protection=full\n", g_target[0],g_target[1],g_target[2],g_target[3]);
        return 3;
    }
    for (int k=0;k<5;k++) if (g_pad[k]!=0x90) {
        printf("pad byte %d = %02x, not nop --- rebuild with "
               "-fpatchable-function-entry=5,0\n", k, g_pad[k]); return 3;
    }
    long d = (long)((char*)test_tramp - (char*)(g_pad+5));
    if (d < -2000000000L || d > 2000000000L) { puts("trampoline out of rel32 range"); return 3; }

    g_memfd = open("/proc/self/mem", O_RDWR);
    if (g_memfd < 0) { perror("open /proc/self/mem"); return 1; }

    syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
    struct sigaction ta = {0};
    ta.sa_sigaction = trap_handler; ta.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &ta, NULL);

    printf("  REAL private .text, patched via /proc/self/mem\n"
           "  cores=%d workers=%d seconds=%d widen=%d mode=%s  target=%p tramp=%p\n",
           ncpu, nworkers, seconds, g_widen,
           g_mode==0?"UNSAFE opcode-first":"text_poke_bp",
           (void*)g_target, (void*)test_tramp);

    pthread_t th[256], ar;
    for (int w = 0; w < nworkers && w < 256; w++) {
        pthread_create(&th[w], NULL, worker, NULL);
        cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(w % ncpu, &cs);
        pthread_setaffinity_np(th[w], sizeof cs, &cs);
    }
    pthread_create(&ar, NULL, armer, NULL);
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(nworkers % ncpu, &cs);
    pthread_setaffinity_np(ar, sizeof cs, &cs);

    for (int e = 0; e < seconds; e += 30) {
        int chunk = (seconds - e) < 30 ? (seconds - e) : 30;
        sleep(chunk);
        long f = __atomic_load_n(&g_faults, __ATOMIC_RELAXED);
        long c = __atomic_load_n(&g_corrupt, __ATOMIC_RELAXED);
        printf("  [%4ds] calls=%-12ld cycles=%-10ld traps=%-11ld faults=%ld corrupt=%ld\n",
               e + chunk, __atomic_load_n(&g_calls,__ATOMIC_RELAXED),
               __atomic_load_n(&g_cycles,__ATOMIC_RELAXED),
               __atomic_load_n(&g_traps,__ATOMIC_RELAXED), f, c);
        if (__atomic_load_n(&g_fault_seen, __ATOMIC_RELAXED)) {
            const char *n = g_fsig==SIGSEGV?"SIGSEGV":g_fsig==SIGILL?"SIGILL":g_fsig==SIGBUS?"SIGBUS":"?";
            printf("        first fault: %s  rip=pad%+ld  fault_addr=pad%+ld\n",
                   n, g_frip_off, g_faddr_off);
        }
        fflush(stdout);
    }
    g_stop = 1;
    for (int w = 0; w < nworkers && w < 256; w++) pthread_join(th[w], NULL);
    pthread_join(ar, NULL);

    printf("  calls=%ld  arm/disarm cycles=%ld  int3_traps=%ld\n",
           g_calls, g_cycles, g_traps);
    printf("  FAULTS=%ld  CORRUPT_RETURNS=%ld\n", g_faults, g_corrupt);
    long bad = g_faults + g_corrupt;
    if (g_mode == 0)
        printf("\n  %s\n", bad ? "TEETH PROVEN on real text: the unsafe swap was caught"
                                 : "NO DETECTION: harden the window (raise widen)");
    else
        printf("\n  %s\n", bad ? "text_poke_bp FAILED on real private text"
                                 : "text_poke_bp CLEAN on real private .text via /proc/self/mem");
    /* mode 0 wants bad!=0 (teeth); mode 2 wants bad==0 (clean) */
    return (g_mode==0) ? (bad?0:1) : (bad?1:0);
}
