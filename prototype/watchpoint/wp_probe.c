/*
 * wp_probe.c --- can a hardware watchpoint deliver into something that runs a program,
 *                without a signal handler, on the kernel TMM actually runs on?
 *
 * WHY THIS EXISTS, OUTSIDE TMM. hook-types-plan.md §2.4 ranks hardware watchpoints as the
 * biggest scope gain available: a debug register watches an arbitrary address, so no compiler
 * pad is needed, which lifts the single constraint that defines the current mechanism's reach.
 * OpenSSL's 1,781 linked symbols in this binary are unarmable today whatever flaw is found in
 * them, because nothing outside TMM core was built with entry padding.
 *
 * The same section calls the risk high and names the reason: "a signal handler as the delivery
 * path, and that is the real objection. SIGTRAP arriving anywhere in a run-to-completion poll
 * loop is a different safety problem from a `call` at a known instruction boundary."
 *
 * THAT OBJECTION ASSUMES SIGNALS, AND perf_event_open MAY NOT NEED THEM. A breakpoint event
 * can sample into an mmap'd ring buffer that a DIFFERENT thread drains. The watched thread
 * takes a trap and continues; no handler runs in it; async-signal-safety never enters the
 * picture. If that works, the risk assessment for this whole hook type changes.
 *
 * So this program does not assume. It asks, in order:
 *
 *   1. Is perf_event_open with PERF_TYPE_BREAKPOINT permitted at all here?
 *      perf_event_paranoid is 4 on both x86 boxes, which is more restrictive than anything
 *      the Linux tree defines (-1..3), so this may simply be refused. Report the errno rather
 *      than inferring from the sysctl.
 *   2. If permitted, does a WRITE watchpoint actually fire on a store to the address?
 *   3. Can the notification be drained from the ring by another thread, with no signal?
 *   4. How many can be armed at once before the kernel refuses --- the claim is four.
 *   5. What does a hit cost the watched thread?
 *
 * NOTHING HERE TOUCHES TMM. It watches its own variable in its own process. That is the point
 * of prototyping outside: find out whether the delivery path is survivable before anyone
 * proposes it near a data plane.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static long
perf_open(struct perf_event_attr *a, pid_t pid, int cpu, int grp, unsigned long flags)
{
    return syscall(__NR_perf_event_open, a, pid, cpu, grp, flags);
}

/* The variable being watched. Volatile so the stores below are not optimised away --- a
 * watchpoint on an address the compiler decided not to write to would report nothing and
 * look like a kernel refusal. */
static volatile uint64_t g_watched;

static int
open_write_watch(void *addr, int len, int sample)
{
    struct perf_event_attr a;

    memset(&a, 0, sizeof a);
    a.type           = PERF_TYPE_BREAKPOINT;
    a.size           = sizeof a;
    a.bp_type        = HW_BREAKPOINT_W;      /* fire on a STORE to this address */
    a.bp_addr        = (uint64_t)(uintptr_t)addr;
    a.bp_len         = len;                  /* HW_BREAKPOINT_LEN_8 etc         */
    a.sample_period  = 1;                    /* every hit, not a sampled subset */
    a.wakeup_events  = 1;
    a.disabled       = 1;
    a.exclude_kernel = 1;
    a.exclude_hv     = 1;
    if (sample) {
        /* Enough to identify WHICH watchpoint fired and where. IP is what a real consumer
         * would use to attribute the store to a call site. */
        a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
    }
    /* pid 0 = this process, cpu -1 = wherever it runs. That is the per-process form, which is
     * the least privileged thing perf_event_open can be asked for. */
    return (int)perf_open(&a, 0, -1, -1, 0);
}

int
main(void)
{
    printf("wp_probe --- hardware watchpoint delivery, outside TMM\n");
    printf("  arch          : %s\n", sizeof(void *) == 8 ? "64-bit" : "32-bit");
    {
        FILE *f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
        int p = -99;
        if (f) { if (fscanf(f, "%d", &p) != 1) p = -99; fclose(f); }
        printf("  paranoid      : %d\n", p);
    }

    /* --- 1. is it permitted at all? ------------------------------------------------ */
    printf("\n1. perf_event_open(PERF_TYPE_BREAKPOINT) on our own process\n");
    int fd = open_write_watch((void *)&g_watched, HW_BREAKPOINT_LEN_8, 1);
    if (fd < 0) {
        printf("   REFUSED: %s (errno %d)\n", strerror(errno), errno);
        printf("   So the ring-buffer delivery path is not available here, and the only\n");
        printf("   remaining mechanisms are ptrace (which STOPS the watched thread) or a\n");
        printf("   signal handler --- which is the objection hook-types-plan.md §2.4 raises.\n");
        return 2;
    }
    printf("   OK, fd=%d --- permitted without extra privilege\n", fd);

    /* --- 2/3. does it fire, and can it be drained without a signal? ---------------- */
    long pgsz = sysconf(_SC_PAGESIZE);
    size_t maplen = (size_t)pgsz * 9;        /* 1 header page + 8 data pages */
    void *ring = mmap(NULL, maplen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        printf("\n2. mmap of the sample ring FAILED: %s\n", strerror(errno));
        printf("   Counting still works, but per-hit records do not, so a program could be\n");
        printf("   told THAT something happened and never WHAT.\n");
        close(fd);
        return 3;
    }
    struct perf_event_mmap_page *hdr = ring;

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    printf("\n2. arm it, then store to the watched address 5 times\n");
    uint64_t before = hdr->data_head;
    for (int i = 0; i < 5; i++)
        g_watched = (uint64_t)i;             /* each store should trip the watchpoint */
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t count = 0;
    if (read(fd, &count, sizeof count) != (ssize_t)sizeof count)
        count = (uint64_t)-1;
    printf("   counter reads : %llu  (expected 5)\n", (unsigned long long)count);
    printf("   ring advanced : %llu bytes  (head %llu -> %llu)\n",
           (unsigned long long)(hdr->data_head - before),
           (unsigned long long)before, (unsigned long long)hdr->data_head);
    if (hdr->data_head == before)
        printf("   NO SAMPLES --- the hit was counted but not described.\n");
    else
        printf("   SAMPLES PRESENT --- and no signal handler was installed to get them.\n");

    munmap(ring, maplen);
    close(fd);

    /* --- 4. how many at once? ------------------------------------------------------ */
    printf("\n4. how many can be armed at once (the claim is four)\n");
    enum { TRY = 12 };
    static volatile uint64_t targets[TRY];
    int fds[TRY], n = 0;
    for (int i = 0; i < TRY; i++) {
        fds[i] = open_write_watch((void *)&targets[i], HW_BREAKPOINT_LEN_8, 0);
        if (fds[i] < 0) {
            printf("   armed %d, the %dth was refused: %s\n", n, n + 1, strerror(errno));
            break;
        }
        n++;
    }
    if (n == TRY)
        printf("   armed all %d --- no ceiling hit at this count\n", n);
    for (int i = 0; i < n; i++)
        close(fds[i]);

    printf("\nWhat this settles, and what it does not:\n");
    printf("  settled  : whether the kernel here permits a breakpoint event at all, whether\n");
    printf("             hits can be described rather than merely counted, and the real\n");
    printf("             concurrency ceiling.\n");
    printf("  NOT here : per-hit cost, behaviour under a run-to-completion poll loop, and\n");
    printf("             whether a uBPF program can run from the consumer. Those come next,\n");
    printf("             and only if the above says the path exists.\n");
    return 0;
}
