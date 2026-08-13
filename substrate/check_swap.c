/* Rung 1 of safe-swap-plan.md: a stress harness that provokes the code-patch
 * race, and an intentionally-UNSAFE swap (opcode-first) to prove the harness has
 * teeth. Many worker threads hammer a function while one thread arms/disarms it.
 * A worker that faults, or sees a return that is neither the body's value nor the
 * safe-return value, is the race caught. If the UNSAFE version does not produce
 * that, the harness is not provoking hard enough and must be hardened. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <linux/membarrier.h>

static void sync_cores(void)
{
    syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
}

extern void test_tramp(void);          /* the validated trampoline stub */
extern volatile int g_tramp_hits, g_skip_body;

typedef uint64_t (*fn2)(uint64_t,uint64_t);
static uint8_t *g_target;              /* the function under test (in a shared page) */
static volatile int g_stop;
static _Atomic long g_faults, g_corrupt, g_calls, g_cycles;

/* per-thread recovery point so a faulting worker can be counted and continue */
static __thread sigjmp_buf g_jb;
static __thread int g_in_call;
static _Atomic long g_traps;
static uint8_t *g_pad;                 /* the 5 bytes being patched */

static void
trap_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si;
    ucontext_t *c = (ucontext_t*)uc;
    uint8_t *rip = (uint8_t*)c->uc_mcontext.gregs[REG_RIP];
    if (rip == g_pad + 1) {            /* trapped ON our INT3 (rip is past it) */
        c->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)(g_pad + 5); /* -> body */
        __atomic_fetch_add(&g_traps, 1, __ATOMIC_RELAXED);
        return;
    }
    _exit(4);                          /* INT3 somewhere unexpected */
}

static void
fault_handler(int sig)
{
    (void)sig;
    if (g_in_call) {
        __atomic_fetch_add(&g_faults, 1, __ATOMIC_RELAXED);
        siglongjmp(g_jb, 1);
    }
    _exit(2);                          /* fault outside a call: real bug */
}

/* UNSAFE arm: opcode FIRST, then displacement, no barrier. Maximises the torn-
 * read window on purpose. Page is already RWX+shared, so plain stores suffice. */
static volatile int g_widen;          /* spins between the two stores */
static volatile int g_mode;            /* 0 = unsafe opcode-first, 1 = safe opcode-last */

static void
do_arm(void *fn, void *tramp)
{
    uint8_t *pad = (uint8_t*)fn + 4;   /* after endbr64 */
    int32_t d = (int32_t)((uint8_t*)tramp - (pad + 5));
    if (g_mode == 0) {                 /* UNSAFE: opcode first */
        __atomic_store_n(pad, (uint8_t)0xe8, __ATOMIC_RELAXED);
        for (volatile int z = 0; z < g_widen; z++) { }
        memcpy(pad + 1, &d, 4);
    } else if (g_mode == 1) {          /* opcode-last (also unsafe -- proven) */
        memcpy(pad + 1, &d, 4);
        for (volatile int z = 0; z < g_widen; z++) { }
        __atomic_store_n(pad, (uint8_t)0xe8, __ATOMIC_RELEASE);
    } else {                           /* mode 2: text_poke_bp */
        __atomic_store_n(pad, (uint8_t)0xcc, __ATOMIC_RELEASE); /* INT3 first */
        sync_cores();
        for (volatile int z = 0; z < g_widen; z++) { }
        memcpy(pad + 1, &d, 4);        /* now safe: any core traps on the cc */
        sync_cores();
        __atomic_store_n(pad, (uint8_t)0xe8, __ATOMIC_RELEASE); /* real opcode over cc */
        sync_cores();
    }
}
static void
do_disarm(void *fn)
{
    uint8_t *pad = (uint8_t*)fn + 4;
    if (g_mode < 2) {                  /* naive */
        __atomic_store_n(pad, (uint8_t)0x90, __ATOMIC_RELEASE);
        memset(pad + 1, 0x90, 4);
    } else {                           /* text_poke_bp in reverse */
        __atomic_store_n(pad, (uint8_t)0xcc, __ATOMIC_RELEASE);
        sync_cores();
        memset(pad + 1, 0x90, 4);
        sync_cores();
        __atomic_store_n(pad, (uint8_t)0x90, __ATOMIC_RELEASE);
        sync_cores();
    }
}

static void *
worker(void *arg)
{
    (void)arg;
    struct sigaction sa = {0};
    sa.sa_handler = fault_handler;
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
            if (r != 103 && r != 0)     /* body=103, safe-return=0; else corrupt */
                __atomic_fetch_add(&g_corrupt, 1, __ATOMIC_RELAXED);
        } else {
            g_in_call = 0;              /* recovered from a fault */
        }
    }
    return NULL;
}

static void *
armer(void *arg)
{
    (void)arg;
    while (!g_stop) {
        do_arm(g_target, (void*)test_tramp);
        do_disarm(g_target);
        __atomic_fetch_add(&g_cycles, 2, __ATOMIC_RELAXED);
    }
    return NULL;
}

int
main(int argc, char **argv)
{
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    int nworkers = (argc > 1) ? atoi(argv[1]) : (ncpu > 2 ? ncpu - 1 : 1);
    int seconds = (argc > 2) ? atoi(argv[2]) : 5;
    g_widen = (argc > 3) ? atoi(argv[3]) : 0;
    g_mode  = (argc > 4) ? atoi(argv[4]) : 0;

    /* shared exec page near the trampoline, in rel32 range (proven setup) */
    void *hint = (void*)(((uintptr_t)test_tramp - 0x100000) & ~0xfffUL);
    g_target = mmap(hint, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                    MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (g_target == MAP_FAILED) { perror("mmap"); return 1; }
    long d = (long)((char*)test_tramp - (char*)g_target);
    if (d < -2000000000L || d > 2000000000L) { puts("mmap hint not honoured"); return 3; }

    int i = 0;
    g_target[i++]=0xf3;g_target[i++]=0x0f;g_target[i++]=0x1e;g_target[i++]=0xfa; /* endbr64 */
    for (int k=0;k<5;k++) g_target[i++]=0x90;                                    /* pad */
    g_target[i++]=0xb8;g_target[i++]=103;g_target[i++]=0;g_target[i++]=0;g_target[i++]=0; /* mov $103,%eax */
    g_target[i++]=0xc3;                                                          /* ret */
    __builtin___clear_cache((char*)g_target, (char*)g_target+i);
    g_pad = g_target + 4;
    syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
    struct sigaction ta = {0};
    ta.sa_sigaction = trap_handler; ta.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &ta, NULL);

    printf("  cores=%d workers=%d seconds=%d widen=%d mode=%s\n",
           ncpu, nworkers, seconds, g_widen,
           g_mode==0?"UNSAFE opcode-first":g_mode==1?"opcode-last":"text_poke_bp");

    pthread_t th[256], ar;
    for (int w = 0; w < nworkers && w < 256; w++) {
        pthread_create(&th[w], NULL, worker, NULL);
        cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(w % ncpu, &cs);
        pthread_setaffinity_np(th[w], sizeof cs, &cs);
    }
    pthread_create(&ar, NULL, armer, NULL);
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET((nworkers) % ncpu, &cs);
    pthread_setaffinity_np(ar, sizeof cs, &cs);

    time_t t0 = 0; /* Date/time unavailable to derive; use elapsed via loop */
    for (int e = 0; e < seconds; e += 30) {
        int chunk = (seconds - e) < 30 ? (seconds - e) : 30;
        sleep(chunk);
        long f = __atomic_load_n(&g_faults, __ATOMIC_RELAXED);
        long c = __atomic_load_n(&g_corrupt, __ATOMIC_RELAXED);
        printf("  [%4ds] calls=%-12ld cycles=%-10ld traps=%-10ld faults=%ld corrupt=%ld\n",
               e + chunk, __atomic_load_n(&g_calls,__ATOMIC_RELAXED),
               __atomic_load_n(&g_cycles,__ATOMIC_RELAXED),
               __atomic_load_n(&g_traps,__ATOMIC_RELAXED), f, c);
        fflush(stdout);
        if ((f + c) && g_mode == 2) { printf("  SOAK FAILED at %ds\n", e+chunk); }
    }
    (void)t0;
    g_stop = 1;
    for (int w = 0; w < nworkers && w < 256; w++) pthread_join(th[w], NULL);
    pthread_join(ar, NULL);

    printf("  calls=%ld  arm/disarm cycles=%ld\n", g_calls, g_cycles);
    printf("  FAULTS=%ld  CORRUPT_RETURNS=%ld  int3_traps=%ld\n", g_faults, g_corrupt, g_traps);
    long bad = g_faults + g_corrupt;
    if (g_mode == 0) {
        printf("\n  %s\n", bad ? "TEETH PROVEN: the unsafe swap was caught"
                                 : "NO DETECTION: harness not provoking -- harden it");
        return bad ? 0 : 1;
    } else if (g_mode == 2) {
        printf("\n  %s\n", bad ? "text_poke_bp FAILED"
                                 : "text_poke_bp CLEAN under the widened window (traps handled)");
        return bad ? 1 : 0;
    } else {
        printf("\n  %s\n", bad ? "SAFE SWAP FAILED: opcode-last did NOT prevent the torn read"
                                 : "SAFE: opcode-last clean under the same widened window");
        return bad ? 1 : 0;
    }
}
