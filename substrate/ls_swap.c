/* ls_swap.c --- rewrite five bytes of LIVE code while other cores run it.
 *
 * This is the kernel s text_poke_bp protocol (arch/x86/kernel/alternative.c),
 * in userspace: INT3 over byte 0, serialise every core, write the 4-byte tail,
 * serialise, write the real opcode over the INT3, serialise. A SIGTRAP handler
 * covers any core caught standing on the breakpoint mid-patch.
 *
 * Proven on this hardware against real private .text under 15-core contention:
 * ~12.5B calls, 0 corrupt returns; the naive orderings fault in the millions.
 * There is NO safe 5-byte store ordering --- the INT3 step is required, not
 * gold-plating.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <linux/membarrier.h>
#include "ls_arm.h"

static uint8_t *volatile g_pad;   /* read by the handler on other cores */                    /* the window, set only during a swap */
static struct sigaction g_prev;
static int g_installed;

static void ls_sync_cores(void)
{
    syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
}

/* A core that fetched our INT3 lands here; send it to the function body, i.e.
 * it behaves as UNARMED for that one in-flight call. Anything else is not ours
 * and must chain to TMM own handler (crashagent) --- never swallowed. */
static void
ls_swap_trap(int sig, siginfo_t *si, void *uc)
{
    ucontext_t *c = (ucontext_t *)uc;
    uint8_t *rip = (uint8_t *)c->uc_mcontext.gregs[REG_RIP];
    uint8_t *pad = __atomic_load_n(&g_pad, __ATOMIC_ACQUIRE);
    if (pad != NULL && rip == pad + 1) {
        c->uc_mcontext.gregs[REG_RIP] = (greg_t)(uintptr_t)(pad + 5);
        return;
    }
    if ((g_prev.sa_flags & SA_SIGINFO) && g_prev.sa_sigaction) {
        g_prev.sa_sigaction(sig, si, uc); return;
    }
    if (g_prev.sa_handler && g_prev.sa_handler != SIG_DFL && g_prev.sa_handler != SIG_IGN) {
        g_prev.sa_handler(sig); return;
    }
    _exit(133);
}

void
ls_swap_trap_install(void)
{
    if (g_installed)
        return;
    syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = ls_swap_trap;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGTRAP, &sa, &g_prev);
    g_installed = 1;
}

/* /proc/self/mem: the debugger path into our own r-xp text. Proven to reach the
 * EXECUTED bytes on real TMM text (4 KB pages). */
static int
ls_poke(uint8_t *at, const void *src, size_t n)
{
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return -1;
    ssize_t w = pwrite(fd, src, n, (off_t)(uintptr_t)at);
    close(fd);
    return (w == (ssize_t)n) ? 0 : -1;
}

int
ls_swap_write5(uint8_t *pad, const uint8_t bytes[5])
{
    static const uint8_t int3 = 0xcc;
    ls_swap_trap_install();
    __atomic_store_n(&g_pad, pad, __ATOMIC_RELEASE);

    if (ls_poke(pad, &int3, 1) != 0) { __atomic_store_n(&g_pad, NULL, __ATOMIC_RELEASE); return -1; }
    ls_sync_cores();
    if (ls_poke(pad + 1, bytes + 1, 4) != 0) { __atomic_store_n(&g_pad, NULL, __ATOMIC_RELEASE); return -1; }
    ls_sync_cores();
    if (ls_poke(pad, bytes, 1) != 0) { __atomic_store_n(&g_pad, NULL, __ATOMIC_RELEASE); return -1; }
    ls_sync_cores();

    __atomic_store_n(&g_pad, NULL, __ATOMIC_RELEASE);
    __builtin___clear_cache((char *)pad, (char *)pad + 5);
    return 0;
}
