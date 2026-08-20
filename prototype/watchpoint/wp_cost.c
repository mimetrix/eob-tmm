/*
 * wp_cost.c --- what does a hardware watchpoint hit cost the WATCHED thread?
 *
 * hook-types-plan.md §2.5 compares pad-based arming against watchpoints and says of the
 * per-hit cost: "The ratio ... is large --- a kernel trap and signal delivery against a call
 * instruction --- but it is UNMEASURED here and no number should be quoted for it."
 *
 * This measures it, for the ring-buffer delivery wp_probe.c established is available (with
 * privilege): no signal handler, the kernel records a sample and the thread continues.
 *
 * METHOD. Time N stores to a variable with the watchpoint DISARMED, then the identical loop
 * with it ARMED, and take the difference per store. Both loops touch the same address, the
 * same cache line, the same instruction stream --- the only difference is whether the debug
 * register is watching. Disarmed-first then armed avoids attributing cold-cache cost to the
 * watchpoint.
 *
 * WHY THE MINIMUM, NOT THE MEAN. Same reason the shield bench reports a minimum: a single
 * rdtsc pair spanning a context switch dominates any average, and on this box that showed up
 * as means 2-3x the min with maxima in the millions. Here the per-store cost is small enough
 * that the loop is timed as a whole and divided, which is less sensitive --- but the run-to-run
 * spread is reported so the reader can see the noise rather than trust one number.
 *
 * WHAT THIS IS NOT. It is not the cost of running a program in response. It is the cost the
 * WATCHED thread pays for the trap, which is the part that would land in TMM's poll loop. A
 * consumer draining the ring pays separately, on another thread, and that is the cost that can
 * be moved off the data path --- which is the whole reason ring delivery matters.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define STORES 200000

static volatile uint64_t g_watched;

static uint64_t
now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

static uint64_t
run_stores(void)
{
    uint64_t t0 = now_ns();
    for (int i = 0; i < STORES; i++)
        g_watched = (uint64_t)i;
    return now_ns() - t0;
}

int
main(void)
{
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type           = PERF_TYPE_BREAKPOINT;
    a.size           = sizeof a;
    a.bp_type        = HW_BREAKPOINT_W;
    a.bp_addr        = (uint64_t)(uintptr_t)&g_watched;
    a.bp_len         = HW_BREAKPOINT_LEN_8;
    a.sample_period  = 1;
    a.wakeup_events  = 1;
    a.disabled       = 1;
    a.exclude_kernel = 1;
    a.exclude_hv     = 1;
    a.sample_type    = PERF_SAMPLE_IP | PERF_SAMPLE_TID;

    int fd = (int)syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
    if (fd < 0) {
        printf("perf_event_open refused: %s --- run with privilege (see wp_probe)\n",
               strerror(errno));
        return 2;
    }
    /* A big ring, because at one sample per store a small one overflows and the kernel then
     * throttles --- which would make the armed loop look FASTER than it is. */
    long pgsz = sysconf(_SC_PAGESIZE);
    size_t maplen = (size_t)pgsz * 1025;
    void *ring = mmap(NULL, maplen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        return 3;
    }
    struct perf_event_mmap_page *hdr = ring;

    printf("wp_cost --- %d stores per pass, ring delivery, no signal handler\n\n", STORES);
    printf("  pass   disarmed(ns/store)   armed(ns/store)   delta(ns)   samples\n");

    double best_delta = 1e18, worst_delta = -1e18;
    for (int pass = 0; pass < 5; pass++) {
        /* warm both paths so neither pays a cold cache */
        (void)run_stores();

        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        uint64_t off_ns = run_stores();

        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        uint64_t h0 = hdr->data_head;
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        uint64_t on_ns = run_stores();
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        uint64_t produced = hdr->data_head - h0;

        double off_per = (double)off_ns / STORES;
        double on_per  = (double)on_ns  / STORES;
        double delta   = on_per - off_per;
        if (delta < best_delta)  best_delta = delta;
        if (delta > worst_delta) worst_delta = delta;
        printf("  %4d   %17.1f   %15.1f   %9.0f   %llu bytes\n",
               pass + 1, off_per, on_per, delta, (unsigned long long)produced);
    }

    printf("\n  per-hit cost to the WATCHED thread: %.0f - %.0f ns\n", best_delta, worst_delta);
    printf("\n  For comparison, measured on this project's own hook: a shield program runs in\n");
    printf("  <= 11 ns on the JIT path, reached by a direct call with no kernel involvement.\n");
    printf("  This number is the trap alone --- it does not include running any program.\n");

    munmap(ring, maplen);
    close(fd);
    return 0;
}
