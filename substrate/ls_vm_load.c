/*
 * ls_vm_load.c --- load a program into a RUNNING TMM.
 *
 * This is the step that separates the demonstration from a patch. Rungs:
 *
 *   1. compiled in                 -> rebuild, repackage, redeploy
 *   2. LS_SHIELD_PATH at startup   -> no rebuild, but a restart
 *   3. THIS FILE                   -> no rebuild, no restart, no window
 *
 * =====================================================================
 *  WHAT THIS DELIBERATELY DOES NOT DO --- read before enabling it
 * =====================================================================
 *
 *  NO SIGNATURE VERIFICATION. `sig_verify()` is declared in shield_abi.h and
 *  has no implementation (scope item 4, deferred by decision). Anything that can
 *  reach this socket can put executable content into the data plane. That is why
 *  it is OFF unless LS_LOAD_SOCKET is set, why the socket is created 0600, and
 *  why every accepted load logs the fact that it was not verified. Do not let
 *  this reach a build anyone else runs.
 *
 *  NO RECLAMATION. A swapped-out VM is never freed. Freeing it requires knowing
 *  that no core is still executing it, which is the cross-core rendezvous of
 *  development-scope.md items 0b/0c and is not written. Leaking is the honest
 *  choice here: bounded by the number of loads, and it cannot corrupt anything.
 *  A load loop would eventually exhaust memory --- that is a real limit, stated
 *  rather than hidden.
 *
 *  NO SAFE POINT. The swap is a single atomic pointer store, which is why it is
 *  safe *enough* without one: a call in flight keeps using the VM it loaded at
 *  entry, and the next call picks up the new one. That gives atomic-per-call
 *  replacement, NOT the ordered cross-core publish item 0 specifies. For one
 *  hook and one program it is sufficient; for a multi-hook coordinated update it
 *  is not, and the difference is exactly item 0.
 *
 * The thread is a real design choice, not laziness: preparation --- create the
 * VM, read the ELF, check the O14 identity, JIT if asked --- is unbounded work
 * that must never happen on the poll loop. It happens here, and the poll loop
 * only ever sees a pointer that is either the old program or the new one.
 */

#include "ls_vm.h"
#include "ls_ctx_reg.h"
#include "ls_map.h"
/* This file OWNS the map glue's state --- see ls_map_glue.h. Exactly one TU may
 * define this; a second one fails the link on a duplicate symbol. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include "ls_arm.h"
#include "ls_shield_blob.h"
#include <stdlib.h>

extern void ls_trampoline_entry(void);
#include "ls_vm_config.h"
#include "shield_abi.h"

#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* Bounded so a malformed length field cannot make us allocate arbitrarily.
 * prog_len arrives from outside and is read before anything authenticates it,
 * which is the exact shape finding O8 was filed about --- so it is checked
 * against the bytes actually received, not trusted. */
#define LS_LOAD_MAX (1u << 20)

/* ------------------------------------------------------------------------
 * Preparation handoff: loader thread -> TMM thread.
 *
 * ubpf_create/ubpf_load_elf/ubpf_compile all allocate, and allocation on a
 * thread we created hangs forever inside TMM's allocator (kern/malloc.c:48 ->
 * init_thread_cache -> spin_lock on a lock nothing ever spin_init'd, because
 * sthread_handler_register is only called by if_xnet.c and BNK has no xnet).
 * Measured, not inferred: the loader goes on-CPU and never returns.
 *
 * So the loader does no preparation. It parks a request here and a TMM thread
 * --- where umalloc works --- performs it.
 * --------------------------------------------------------------------- */
#define LS_PREP_IDLE     0
#define LS_PREP_PENDING  1
#define LS_PREP_DONE     2

/* B6: bound what one request may ask a poll iteration to do. Prepare cost is
 * dominated by program size once the scratch is right-sized, so an unbounded
 * length is an unbounded stall. 256 KB is far above any real shield (the
 * built-in one is 4320 bytes) and far below anything that would matter. */
#define LS_PREP_MAX_PROG (256u * 1024u)


/* How long the loader waits before giving up. A prepare that never completes
 * means the owning TMM thread is not running its timers; say so rather than
 * hanging the way this code used to. */
#define LS_PREP_WAIT_MS  5000

/*
 * WHICH PIECE OF WORK THE TMM THREAD IS BEING ASKED TO DO.
 *
 * ONE request struct and ONE state machine for both, rather than a second copy of the
 * handoff. The socket is serial, so "one outstanding at a time" is already the model, and
 * the subtle parts here --- the IDLE/PENDING/DONE transitions, the timeout that deliberately
 * leaves a late request PENDING, the refusal when one is already outstanding --- are exactly
 * what a parallel implementation would get subtly wrong.
 */
#define LS_PREP_OP_RELOAD 0
#define LS_PREP_OP_BENCH  1

/*
 * BENCH RUNS N ITERATIONS INSIDE A POLL ITERATION, which RELOAD does not, so it needs its own
 * bound. ls_vm_bench_program creates a VM, JITs, executes `iters` times and destroys it, all
 * on the TMM thread that picks the request up --- because that is the only thread where
 * umalloc works. Every one of those iterations is time that thread is not polling.
 *
 * At a plausible tens-of-nanoseconds per call, 10,000 iterations is well under a millisecond;
 * the prepare timer's own period is 10 ms. But "plausible" is doing the work in that sentence
 * --- the per-call cost is the number this op exists to establish, so the stall cannot be
 * computed in advance from anything but a guess. The cap is therefore set where a pessimistic
 * 1 us per call would still stall one thread for 20 ms rather than seconds.
 *
 * This is a DEVELOPMENT op. It briefly stalls one TMM thread on purpose, and it must not
 * appear in a control plane. The header above this switch says the same about all the 0x100x
 * ops; this one now has a reason beyond taste.
 */
#define LS_PREP_BENCH_MAX_ITERS 20000u

struct ls_prep {
    volatile int state;          /* LS_PREP_* --- the only cross-thread word    */
    int          op;             /* LS_PREP_OP_*                                */
    int          slot;
    const void  *prog;           /* into the loader's mmap scratch; alive until DONE */
    unsigned int prog_len;
    unsigned char mode;
    char         section[80];
    char         function[64];
    unsigned int iters;          /* bench only                                  */
    uint64_t     bmin, bmean, bmax;   /* bench results                          */
    int          bjitted;        /* 1 = the JIT was measured, 0 = the interpreter.
                                  * Reported to the client, because a number from
                                  * the interpreter is not a hook cost and nothing
                                  * else in the reply would say so. */
    int          rc;             /* slot on success, negative on refusal        */
};

/* What the loader reads back. COPIED OUT before the slot returns to IDLE, so a caller can
 * never read results that a subsequent request has begun overwriting. The socket is serial
 * today and this costs three words. */
struct ls_prep_result {
    int      rc;
    uint64_t bmin, bmean, bmax;
    int      jitted;
};

static struct ls_prep g_prep;

/* Set by ls_prep.c once a TMM thread owns the timer. Read here only to refuse a
 * load that could never be serviced. */
int ls_prep_timer_on;

/* Provided by ls_prep.c, which is compiled in TMM's include world because the
 * timer and `tid` live there. Kept to a void(void) so no TMM type crosses into
 * this file --- it is built STDINC and syntax-checked standalone. */
extern void ls_prep_timer_start(void);

/* Called from ls_prep.c on a TMM thread. Declared because it is not static. */
void ls_prep_run_pending(void);

/* THE WORK. Called from ls_prep.c's timer callback, so it runs on a TMM thread
 * where umalloc works. Short by construction: it is inside a poll iteration.
 * Lives here rather than there so everything touching the request state stays
 * in one file. */
void
ls_prep_run_pending(void)
{
    if (__atomic_load_n(&g_prep.state, __ATOMIC_ACQUIRE) != LS_PREP_PENDING)
        return;

    /* Everything below allocates. That is the entire point of being here. */
    if (g_prep.op == LS_PREP_OP_BENCH) {
        /* THE FIX THIS STRUCTURE EXISTED FOR ALREADY. ls_vm_bench_program used to be called
         * straight from the loader thread, which hits the identical allocator freeze that
         * this handoff was built to avoid for loads --- the dev ops were simply never
         * converted. Running it wedged the loader (tid RUNNING, on-CPU) while the proxy kept
         * serving, and it is why no per-call shield cost has been quotable from a live TMM:
         * the counter mean measures the scheduler, and the clean number is this op's min. */
        g_prep.rc = ls_vm_bench_program(g_prep.prog, g_prep.prog_len,
                                        g_prep.section, g_prep.function, g_prep.iters,
                                        &g_prep.bmin, &g_prep.bmean, &g_prep.bmax,
                                        &g_prep.bjitted);
    } else {
        g_prep.rc = ls_vm_reload(g_prep.slot, g_prep.prog, g_prep.prog_len,
                                 g_prep.section, g_prep.function,
                                 (enum ls_mode)g_prep.mode);
    }

    __atomic_store_n(&g_prep.state, LS_PREP_DONE, __ATOMIC_RELEASE);
}

/* Loader side. Parks the request, waits for a TMM thread to do it, returns the
 * slot or negative. Allocates nothing --- nanosleep is a syscall, which is the
 * one thing this thread can safely do. */
static int
ls_prep_submit(int op, int slot, const void *prog, unsigned int prog_len,
               const char *section, const char *function, unsigned char mode,
               unsigned int iters, struct ls_prep_result *out, const char **why)
{
    if (!ls_prep_timer_on) {
        *why = "prepare handoff not armed (no TMM thread owns the timer)";
        return -1;
    }
    if (prog_len > LS_PREP_MAX_PROG) {
        *why = "program exceeds the accepted size ceiling";
        return -1;
    }
    /* One request at a time. The socket is serial, so this only trips if a
     * previous prepare never completed. */
    if (__atomic_load_n(&g_prep.state, __ATOMIC_ACQUIRE) != LS_PREP_IDLE) {
        *why = "a previous prepare is still outstanding";
        return -1;
    }

    g_prep.op       = op;
    g_prep.slot     = slot;
    g_prep.prog     = prog;
    g_prep.prog_len = prog_len;
    g_prep.mode     = mode;
    g_prep.iters    = iters;
    g_prep.bmin = g_prep.bmean = g_prep.bmax = 0;
    /* snprintf, not strlcpy: this file is STDINC and strlcpy is not in the
     * standard C library it gets. Both truncate safely and NUL-terminate. */
    snprintf(g_prep.section,  sizeof g_prep.section,  "%s", section);
    snprintf(g_prep.function, sizeof g_prep.function, "%s", function);
    g_prep.rc = -1;

    __atomic_store_n(&g_prep.state, LS_PREP_PENDING, __ATOMIC_RELEASE);

    for (int waited = 0; waited < LS_PREP_WAIT_MS; waited++) {
        if (__atomic_load_n(&g_prep.state, __ATOMIC_ACQUIRE) == LS_PREP_DONE) {
            int rc = g_prep.rc;
            /* COPY BEFORE RELEASING. Once state is IDLE the struct belongs to whoever
             * submits next, so reading g_prep afterwards is a race that the serial socket
             * happens to hide today. Three words is not a price worth paying for that. */
            if (out != NULL) {
                out->rc    = rc;
                out->bmin   = g_prep.bmin;
                out->bmean  = g_prep.bmean;
                out->bmax   = g_prep.bmax;
                out->jitted = g_prep.bjitted;
            }
            __atomic_store_n(&g_prep.state, LS_PREP_IDLE, __ATOMIC_RELEASE);
            if (rc < 0)
                *why = "identity mismatch, malformed ELF, or uBPF rejected it";
            return rc;
        }
        {
            struct timespec ms = { 0, 1000000 };   /* 1 ms */
            nanosleep(&ms, NULL);
        }
    }

    /* Left PENDING deliberately: if the TMM thread is merely late it will still
     * complete, and the next submit is refused rather than racing this one. */
    *why = "timed out waiting for a TMM thread to prepare it";
    return -1;
}

static pthread_t g_loader;
static int       g_loader_running;
static char      g_sock_path[108];

/* Provided by ls_vm.c: prepare a program into a spare slot and publish it over
 * an existing one with a single atomic store. */
extern int  ls_vm_reload(int slot, const void *elf, size_t elf_len,
                         const char *section, const char *function, enum ls_mode m);
extern void ls_vm_set_mode(int slot, enum ls_mode m);

static void
reply(int fd, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0)
        (void)!write(fd, buf, (size_t)n);
}

/* Scratch for one control message, from the kernel rather than from malloc.
 *
 * malloc() is NOT usable on this thread. TMM aliases it to __wrap_malloc
 * (kern/malloc.c:48), which routes every allocation through per-thread or
 * per-core state --- sthread_malloc's stats row, umalloc's per-core arena, or a
 * raw spin_lock on the bootstrap heap. The loader is a plain pthread we
 * created: it is neither a TMM poll thread nor a registered DPDK service
 * thread, so it has none of that state, and the allocator spins. Measured as
 * 20/20 samples of /proc/<tid>/syscall reading "running" --- on-CPU, never in a
 * syscall --- with the arm op wedged before its first line of output.
 *
 * sthread_handler_register() is the supported way to register a foreign thread
 * and is deliberately not used: init_thread_row() (kern/sthread_memory.c:66)
 * leaks thread_stats_lock on both error paths and leaves thread_stats NULL for
 * _sthread_malloc() to dereference. Not a trade worth making for scratch space.
 *
 * mmap keeps the property the previous comment was protecting --- a 1 MB static
 * buffer is 1 MB of resident .bss in EVERY instance, one per core, for a
 * message that arrives approximately never (measured: +15.6% .bss). This
 * mapping is per-connection and released on every exit path. */
static unsigned char *
ls_load_buf_alloc(void)
{
    void *p = mmap(NULL, LS_LOAD_MAX, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : (unsigned char *)p;
}

static void
ls_load_buf_free(unsigned char *p)
{
    if (p != NULL)
        (void)munmap(p, LS_LOAD_MAX);
}

static void
handle(int fd)
{
    unsigned char *g_load_buf = ls_load_buf_alloc();
    if (g_load_buf == NULL) {
        reply(fd, "ERR scratch mmap failed\n");
        return;
    }
    ssize_t n = read(fd, g_load_buf, LS_LOAD_MAX);

    if (n < (ssize_t)sizeof(struct shield_msg)) {
        reply(fd, "ERR short message (%ld bytes)\n", (long)n);
        ls_load_buf_free(g_load_buf);
        return;
    }

    struct shield_msg *m = (struct shield_msg *)g_load_buf;

    /* O8: prog_len is attacker-influenced and is read before authentication.
     * There is no authentication here at all, so the length check is the only
     * thing standing between a bad field and a bad read. Check it against what
     * actually arrived. */
    size_t hdr = sizeof(struct shield_msg);
    if (m->prog_len > (size_t)n - hdr) {
        reply(fd, "ERR prog_len %u exceeds received payload %lu\n",
              m->prog_len, (unsigned long)((size_t)n - hdr));
        ls_load_buf_free(g_load_buf);
        return;
    }

    /* O14, on real code: the binding carries ONE identity --- `hook` --- and the
     * loader needs two, because PREVAIL proved a SECTION and uBPF runs a SYMBOL.
     * Both are synthesised here by convention (section = "fentry/<hook>",
     * function = "shield"), and a convention is exactly what O14 says is not good
     * enough: nothing signed commits to either name, so the identity check in
     * ls_vm_arm is verifying the program against names this loader made up
     * rather than against names an authority asserted. The binding needs both
     * fields. Until it has them, this is the gap, not a detail. */
    char section[96];
    snprintf(section, sizeof section, "fentry/%.63s", m->binding.hook);

    /*
     * THE CTX ABI GATE. Checked for every op that loads or arms, before anything
     * else is looked at.
     *
     * A program is verified by PREVAIL against a ctx STRUCT it was compiled with.
     * The running TMM's builders produce a struct of their own shape. Nothing
     * connected those two facts until now, so a program built against a different
     * layout loaded cleanly, verified cleanly, and read adjacent fields as its own.
     * That is not hypothetical: ls_ctx_rst went 64 -> 92 bytes and gained a flow
     * cookie on 2026-08-17, and the mismatch is silent in both directions.
     *
     * ZERO IS ACCEPTED, DELIBERATELY, AND IT IS A TRANSITION MEASURE. Every client
     * written before this field existed sends a zeroed binding, and refusing those
     * would break the loader the moment this ships while proving nothing --- the
     * problem it guards is a layout mismatch, not an old client. It is logged so the
     * silence is visible, and the acceptance should be removed once ls-load.py and
     * the control plane both set it. TODO(f5): make 0 a refusal.
     *
     * Unsigned, and that is correct for this check. Refusing a forged target needs
     * signature verification (item 4); refusing a mismatched layout does not, because
     * both parties are us and the failure is an honest mistake.
     */
    if (m->binding.ctx_abi_version != 0 &&
        m->binding.ctx_abi_version != SHIELD_CTX_ABI_VERSION) {
        reply(fd, "ERR ctx abi mismatch: program built for %u, this TMM builds %u. "
                  "Recompile the program against this build's headers.\n",
              (unsigned)m->binding.ctx_abi_version,
              (unsigned)SHIELD_CTX_ABI_VERSION);
        fprintf(stderr, "ls_vm: REFUSED --- ctx abi %u, expected %u\n",
                (unsigned)m->binding.ctx_abi_version,
                (unsigned)SHIELD_CTX_ABI_VERSION);
        return;
    }
    if (m->binding.ctx_abi_version == 0)
        fprintf(stderr, "ls_vm: ctx abi UNDECLARED (0) --- accepted, but this TMM "
                        "builds %u and a mismatch would be silent\n",
                (unsigned)SHIELD_CTX_ABI_VERSION);

    switch (m->op) {
    case SHIELD_OP_LOAD: {
        fprintf(stderr,
                "ls_vm: LOAD accepted on %s --- NOT SIGNATURE VERIFIED "
                "(scope item 4 deferred); hook=%.63s bytes=%u\n",
                g_sock_path, m->binding.hook, m->prog_len);
        /* Handed to a TMM thread: preparing here would hang this thread in
         * TMM's allocator. See ls_prep above. */
        const char *why = "unknown";
        /* The slot comes from the request. Hardcoding 0 here meant every LOAD
         * landed on slot 0 no matter what was asked for, so a program written
         * for a tracepoint on another slot loaded "successfully" and then never
         * ran --- the call site emits to its own slot, which stayed empty. The
         * comment under STATUS below already claimed LOAD did this; it did not.
         * Same reasoning for SET_MODE and REVOKE. */
        int slot = ls_prep_submit(LS_PREP_OP_RELOAD, (int)m->epoch, m->prog, m->prog_len,
                                  section, "shield",
                                  m->mode, 0u, NULL, &why);
        if (slot < 0)
            reply(fd, "ERR load refused (%s)\n", why);
        else
            reply(fd, "OK loaded slot=%d mode=%d unverified=yes\n", slot, m->mode);
        break;
    }
    case SHIELD_OP_SET_MODE:
        ls_vm_set_mode((int)m->epoch, (enum ls_mode)m->mode);
        reply(fd, "OK mode=%d\n", m->mode);
        break;

    case SHIELD_OP_STATUS: {
        struct ls_stats st;
        /* slot comes from epoch, as it does for LOAD and ARM. Hardcoding 0
         * made every slot but one invisible, which is a poor property for a
         * mechanism whose whole point is arming several things at once. */
        int qslot = (int)m->epoch;
        if (!ls_vm_stats(qslot, &st)) { reply(fd, "ERR no such slot %d\n", qslot); break; }
        reply(fd, "OK armed=%d mode=%d gen=%u fired=%llu safe_returns=%llu errors=%llu "
                  "cycles=%llu cycles_max=%llu\n",
              (int)st.armed, st.mode, st.gen,
              (unsigned long long)st.fired, (unsigned long long)st.safe_returns,
              (unsigned long long)st.errors, (unsigned long long)st.cycles,
              (unsigned long long)st.cycles_max);
        break;
    }
    /* Ops beyond the ABI's four. shield_msg.op is a uint32 and the enum uses the
     * low values, so these sit well clear --- and they are DEVELOPMENT ops, not
     * proposed additions to the protocol. A real control plane would not expose
     * "benchmark this" or "show me recent inputs" on the load path. */
    case 0x1001: {   /* BENCH: load, measure, discard --- never touches a live slot */
        /* HANDED TO A TMM THREAD, like a load. This called ls_vm_bench_program() directly
         * until 2026-08-19, on the loader thread, where TMM's allocator freezes --- the same
         * failure ls_prep exists to avoid, in the one op that was never converted. It wedged
         * the loader on-CPU, and because the clean per-call figure is this op's MIN, that
         * left the shield's per-invocation cost unquotable from a live TMM: the armed-hook
         * counter mean is dominated by rdtsc pairs spanning context switches (a single call
         * reading 1.09M then 3.14M cycles), so it measures the scheduler and not the hook. */
        struct ls_prep_result r = { -1, 0, 0, 0, 0 };
        const char *why = "?";
        char section[96];
        uint32_t iters;

        snprintf(section, sizeof section, "fentry/%.63s", m->binding.hook);
        iters = m->epoch ? m->epoch : 10000;            /* epoch reused as count */
        if (iters > LS_PREP_BENCH_MAX_ITERS) {
            /* REFUSE rather than clamp. A clamped run reports a smaller sample than was
             * asked for under the same "OK" line, and whoever reads the number will not
             * know. Every other ceiling in this file refuses for the same reason. */
            reply(fd, "ERR bench iters=%u exceeds the ceiling of %u.\n"
                      "    This runs on a TMM thread inside a poll iteration, so the "
                      "iteration count is a stall budget, not a preference.\n",
                  iters, LS_PREP_BENCH_MAX_ITERS);
            break;
        }
        if (ls_prep_submit(LS_PREP_OP_BENCH, -1, m->prog, m->prog_len,
                           section, "shield", 0, iters, &r, &why) != 0) {
            reply(fd, "ERR bench refused (%s)\n", why);
        } else {
            /* `path` in the reply, first, because it changes what the number MEANS. A reader
             * who sees only cycles will read an interpreter figure as a hook cost. */
            reply(fd, "OK bench path=%s iters=%u min=%llu mean=%llu max=%llu cycles bytes=%u\n"
                      "   quote the MIN; the mean is 2-3x it and measures the scheduler\n",
                  r.jitted ? "jit" : "interp",
                  iters, (unsigned long long)r.bmin, (unsigned long long)r.bmean,
                  (unsigned long long)r.bmax, m->prog_len);
        }
        break;
    }
    case 0x1002: {   /* SAMPLES: the last few ctx values the hook actually saw */
        struct ls_ctx_sample sm[LS_CTX_SAMPLES];
        unsigned n2 = ls_vm_samples((int)m->epoch, sm, LS_CTX_SAMPLES);
        if (n2 == 0) { reply(fd, "OK no samples (hook not fired, or LS_VM_SAMPLES unset)\n"); break; }
        for (unsigned i = 0; i < n2; i++) {
            char hex[2 * LS_CTX_SAMPLE_BYTES + 1];
            unsigned k = sm[i].len < LS_CTX_SAMPLE_BYTES ? sm[i].len : LS_CTX_SAMPLE_BYTES;
            for (unsigned j = 0; j < k; j++)
                snprintf(hex + 2 * j, 3, "%02x", sm[i].bytes[j]);
            hex[2 * k] = 0;
            reply(fd, "OK sample seq=%llu len=%u verdict=%u ctx=%s\n",
                  (unsigned long long)sm[i].seq, sm[i].len, sm[i].verdict, hex);
        }
        break;
    }

    case 0x1003: {   /* ARM LIVE --- hook a real function while TMM is RUNNING */
        char a[65];
        memcpy(a, m->binding.hook, 64); a[64] = 0;
        unsigned long long addr = strtoull(a, NULL, 0);
        int slot = (int)m->epoch;
        if (addr == 0) {
            reply(fd, "ERR arm: put the entry address in binding.hook (e.g. 0xcd4700)\n");
            break;
        }
        /*
         * REFUSE TO ARM A SLOT WITH NO PROGRAM. Observed 2026-08-18: a load was
         * correctly refused (the object's section was fentry/rst_why while the request
         * named a different hook --- finding O14 working), and the ARM that followed
         * still reported "OK ARMED LIVE" with armed=0. Live .text on two pods was
         * patched to call a trampoline whose slot held nothing.
         *
         * It is not a crash --- ls_vm_call falls through on an empty slot --- but it is
         * a patch into a running data plane that buys nothing, reported as success. And
         * it is the shape of a worse bug: whoever reads "ARMED LIVE" believes a program
         * is running, so a later "why did nothing fire" hunt looks at traffic instead of
         * at the load that failed a minute earlier.
         *
         * Checked here rather than in ls_arm_live because ls_arm.c knows about pads and
         * trampolines, not about slots holding programs. Structurally it belongs where
         * the two are joined.
         */
        {
            struct ls_stats st;
            if (!ls_vm_stats(slot, &st)) {
                reply(fd, "ERR arm: slot %d out of range\n", slot);
                break;
            }
            if (!st.armed) {
                reply(fd, "ERR arm: slot %d holds NO PROGRAM --- refusing to patch "
                          ".text for a hook that cannot run. Load first; if a load was "
                          "refused, fix that rather than arming over it.\n", slot);
                break;
            }
        }
        /* ls_arm_live rewrites the five pad bytes with the kernel's text_poke_bp
         * protocol, so the poll threads may be executing this function right now. */
        if (ls_arm_live((void *)(uintptr_t)addr, (void *)ls_trampoline_entry, slot) != 0)
            reply(fd, "ERR arm 0x%llx failed (no pad, out of rel32 range, or swap refused)\n", addr);
        else
            reply(fd, "OK ARMED LIVE entry=0x%llx slot=%d (no restart)\n", addr, slot);
        break;
    }
    case 0x1004: {   /* DISARM LIVE --- restore the nops, equally live */
        char a[65];
        memcpy(a, m->binding.hook, 64); a[64] = 0;
        unsigned long long addr = strtoull(a, NULL, 0);
        if (addr == 0) { reply(fd, "ERR disarm: bad address\n"); break; }
        if (ls_disarm_live((void *)(uintptr_t)addr) != 0)
            reply(fd, "ERR disarm 0x%llx failed (not armed?)\n", addr);
        else
            reply(fd, "OK DISARMED LIVE entry=0x%llx\n", addr);
        break;
    }

    case SHIELD_OP_REVOKE:
        /* Disarm is the honest half of revocation. The other half --- reclaiming
         * the program's memory --- needs item 0c. Mode DISABLE stops it running;
         * it does not remove it. */
        ls_vm_set_mode((int)m->epoch, LS_MODE_DISABLE);
        /* Release the revoked program's map shapes. Shapes are recorded per LOAD
         * and LS_MAP_MAX is 4, so without this the fifth program loaded finds the
         * table full and its maps silently do not exist --- indistinguishable from
         * a program whose predicate never matches. */
        ls_map_reset_shapes();
        reply(fd, "OK disabled (not reclaimed --- see item 0c)\n");
        break;

    default:
        reply(fd, "ERR unknown op %d\n", m->op);
    }
    ls_load_buf_free(g_load_buf);
}

void ls_vm_loader_start(void);
void ls_vm_bootstrap(void);

/* Startup, once per TMM thread. Registered by ls_prep.c through TMM's INIT_FUNC
 * linker set, so no F5 source calls it --- see the note there.
 *
 * Lives on this side of the include-world split because ls_vm_init() returns
 * bool and ls_vm_arm_configured() takes size_t. Redeclaring those in TMM's
 * -nostdinc world would risk a genuine ABI mismatch (bool returns in al; reading
 * eax as int does not guarantee the upper bits), so only a void(void) crosses. */
void
ls_vm_bootstrap(void)
{
    if (!ls_vm_init())
        return;   /* VM down; TMM behaves exactly as shipped */

    /* Say how many ctx builders linked, BEFORE anything is armed.
     *
     * A zero count means the linker discarded the ls_ctx_regs section, and then every typed
     * hook silently falls back to the generic five-register context: nothing crashes, programs
     * still run, and the reset and TLS record feeds simply produce nothing. Safe and silent is
     * the pairing that costs days here, so it goes in the log next to the init line where
     * anyone reading a startup log will see it. substrate/check_ctx_reg.c is what fails the
     * build; this is what explains a running system. */
    ls_ctx_reg_report();

    /* Both identities: PREVAIL proved the SECTION, uBPF runs the SYMBOL, and
     * ls_vm_arm refuses unless they are the same program (O14). The _configured
     * form applies the environment overrides --- program source, names, mode ---
     * so changing any of them is a restart rather than a rebuild. */
    (void)ls_vm_arm_configured(ls_shield_blob, sizeof ls_shield_blob,
                               LS_SHIELD_SECTION, LS_SHIELD_FUNCTION);

    /* Runtime load path. Does nothing unless LS_LOAD_SOCKET is set, and it
     * accepts UNVERIFIED programs when it is --- signature verification is
     * scope item 4 and is deferred. */
    ls_vm_loader_start();
}

static void *
loader_thread(void *arg)
{
    (void)arg;

    /* Block signals on this thread. TMM is timer-driven, and an unblocked helper
     * thread has accept() interrupted (EINTR) continuously -- measured as a
     * spinning thread that never accepts a queued connection. Signal handling
     * belongs to the poll threads and crashagent, not here.
     *
     * SIGTRAP is deliberately left UNBLOCKED: the safe swap's breakpoint is a
     * synchronous, thread-directed signal, and blocking it would convert a
     * mid-patch trap into the kernel's fatal default action. */
    sigset_t block;
    sigfillset(&block);
    sigdelset(&block, SIGTRAP);
    sigdelset(&block, SIGSEGV);
    sigdelset(&block, SIGBUS);
    sigdelset(&block, SIGILL);
    sigdelset(&block, SIGFPE);
    pthread_sigmask(SIG_SETMASK, &block, NULL);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "ls_vm: loader socket(): %s\n", strerror(errno));
        return NULL;
    }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", g_sock_path);
    unlink(g_sock_path);

    /* 0600 before anyone can connect: the bind inherits the umask, so set it
     * rather than assume it. This is containment, not authentication --- it
     * limits who can reach an unauthenticated load path to whoever shares the
     * uid, which in this container is root. */
    mode_t old = umask(0177);
    int rc = bind(srv, (struct sockaddr *)&sa, sizeof sa);
    umask(old);
    if (rc < 0 || listen(srv, 4) < 0) {
        fprintf(stderr, "ls_vm: loader bind/listen %s: %s\n", g_sock_path, strerror(errno));
        close(srv);
        return NULL;
    }

    fprintf(stderr,
            "ls_vm: LOADER LISTENING on %s --- accepts UNVERIFIED programs. "
            "This must not exist in a build anyone else runs.\n", g_sock_path);

    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        handle(fd);
        close(fd);
    }
    close(srv);
    return NULL;
}


/* pthreads do not survive fork(): a child keeps the listening socket but loses
 * the thread that was accepting on it, which looks exactly like a hang. Restart
 * it in the child. */
static void
ls_loader_after_fork(void)
{
    g_loader_running = 0;
    ls_vm_loader_start();
}

/* Called from init, off the data path. No socket unless asked for. */
void
ls_vm_loader_start(void)
{
    const char *p = getenv("LS_LOAD_SOCKET");
    if (p == NULL || *p == '\0')
        return;                      /* default: no load path at all */

    /* Every TMM thread reaches here (http_psm_init is per-thread); tid 0 takes
     * the timer. Done before the g_loader_running check so the owner registers
     * even when it is not the thread that created the loader. */
    ls_prep_timer_start();

    if (g_loader_running)
        return;
    /* PER-INSTANCE path. BNK runs one TMM instance per core, each its own
     * process with its own address space, so a single shared path lets only the
     * first instance bind --- the rest fail bind() and their loader thread
     * exits, leaving a socket nobody accepts on. Arming is per-address-space
     * too, so one socket could only ever arm one core. */
    snprintf(g_sock_path, sizeof g_sock_path, "%s.%d", p, (int)getpid());
    if (pthread_create(&g_loader, NULL, loader_thread, NULL) != 0) {
        fprintf(stderr, "ls_vm: could not start loader thread\n");
        return;
    }
    pthread_detach(g_loader);
    g_loader_running = 1;
    static int atfork_done;
    if (!atfork_done) {
        pthread_atfork(NULL, NULL, ls_loader_after_fork);
        atfork_done = 1;
    }
}
