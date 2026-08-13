/* check_selfpatch.c --- the integration gate for Path B (bnk-integration-map.md §2).
 *
 * Question: can a process patch its OWN private r-xp .text so that EXECUTION sees
 * the change? An earlier probe here claimed no --- but it read the byte back with
 * a normal load, and a load and an instruction fetch can see different pages during
 * copy-on-write, so the readback lied. gdb sets breakpoints in r-xp text via
 * /proc/self/mem all day, so this should work; this tests it the only way that
 * counts: write a breakpoint (0xcc) to a real function's pad, then CALL the
 * function and see whether it traps.
 *
 * Three assertions, each with teeth:
 *   [0] control  --- no write        => runs, NO trap  (the trap below is ours, not ambient)
 *   [1] patched  --- 0xcc at the pad => TRAPS, SIGTRAP (the write is fetched/executed)
 *   [2] restored --- original byte   => runs again     (reversible)
 * The pad is patched at offset 4 --- right after endbr64 --- the exact slot
 * -fpatchable-function-entry=5,0 leaves, so this is the real arming surface.
 *
 * Build: gcc -O2 -fcf-protection=full -fpatchable-function-entry=5,0 -o check_selfpatch check_selfpatch.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

static sigjmp_buf jb;
static volatile int got_sig;
static void handler(int s, siginfo_t *si, void *u) { (void)si; (void)u; got_sig = s; siglongjmp(jb, 1); }
static const char *signame(int s) { return s==SIGTRAP?"SIGTRAP":s==SIGSEGV?"SIGSEGV":s==SIGILL?"SIGILL":"other"; }

/* Real out-of-line function; -fpatchable-function-entry gives it endbr64 + 5 nops. */
__attribute__((noinline,used)) static int victim(void) { return 42; }

int
main(void)
{
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &sa, NULL); sigaction(SIGSEGV, &sa, NULL); sigaction(SIGILL, &sa, NULL);

    uint8_t *fn = (uint8_t *)victim;
    printf("entry: %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           fn[0],fn[1],fn[2],fn[3],fn[4],fn[5],fn[6],fn[7],fn[8]);

    /* [0] control: no write must not trap */
    got_sig = 0;
    if (sigsetjmp(jb, 1) == 0) { int r = victim();
        printf("[0] control: victim=%d, %s\n", r, got_sig ? "TRAPPED -- ambient, test invalid" : "no trap (good)"); }
    else printf("[0] control TRAPPED %s -- ambient, test invalid\n", signame(got_sig));

    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) { perror("open /proc/self/mem"); return 1; }

    int off = (fn[0]==0xf3&&fn[1]==0x0f&&fn[2]==0x1e&&fn[3]==0xfa) ? 4 : 0;  /* the pad, after endbr64 */
    printf("patching offset %d (%s)\n", off, off ? "the pad, after endbr64" : "entry byte");
    uint8_t orig, cc = 0xcc;
    if (pread(fd, &orig, 1, (off_t)(uintptr_t)(fn+off)) != 1) { perror("pread"); return 1; }
    ssize_t w = pwrite(fd, &cc, 1, (off_t)(uintptr_t)(fn+off));
    __builtin___clear_cache((char*)(fn+off), (char*)(fn+off)+1);

    /* [1] patched: must trap, specifically SIGTRAP (a real INT3, not a COW fault) */
    got_sig = 0;
    if (sigsetjmp(jb, 1) == 0) { int r = victim();
        printf("[1] pwrite rc=%zd, victim=%d -- write NOT executed\n", w, r); }
    else printf("[1] pwrite rc=%zd, TRAPPED %s -- write IS executed\n", w, signame(got_sig));

    /* [2] restore: original must run again */
    pwrite(fd, &orig, 1, (off_t)(uintptr_t)(fn+off));
    __builtin___clear_cache((char*)(fn+off), (char*)(fn+off)+1);
    got_sig = 0;
    if (sigsetjmp(jb, 1) == 0) { int r = victim();
        printf("[2] restored: victim=%d %s\n", r, r==42 ? "(reversible)" : "!! wrong !!"); }
    else printf("[2] restored but TRAPPED %s -- NOT reversible\n", signame(got_sig));

    close(fd);
    return 0;
}
