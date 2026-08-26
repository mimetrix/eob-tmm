/* ls_map_glue.h --- the three uBPF callbacks that make maps work.
 *
 * Registered on every VM before the ELF is loaded, because the relocation
 * callback has to be in place when uBPF walks the maps section.
 *
 *   relocation    resolve `lddw r1, <map symbol>` to a map INDEX
 *   bounds check  permit reads of map VALUE memory
 *   helpers 1/2/3 the standard BPF map helpers, which PREVAIL already knows
 *
 * ALL FIVE REGISTRATIONS GO THROUGH ls_map_glue_install(), AND THAT IS THE POINT.
 * On 2026-08-17 the registration calls existed only in the build box's copy of
 * ls_vm.c and were never carried back here; copying this tree over that one
 * deleted them. Every symptom pointed elsewhere. The programs still loaded, still
 * ran, still verified --- their maps were simply always empty, which is
 * indistinguishable from a predicate that never matches. What caught it was the
 * build's globals manifest: with nothing calling ls_map_reloc, the compiler
 * removed g_ls_shapes as dead, and the manifest noticed a name it expected was
 * gone. A five-call sequence spread across two arm paths is a sequence that can
 * be half-applied; one function cannot.
 *
 * ORDER MATTERS AND IS EASY TO GET WRONG. ubpf_register_data_relocation must
 * precede ubpf_load_elf_ex; registered after, the maps section has already been
 * walked and every `lddw` still holds the zero clang emitted. The program then
 * runs, calls a helper with map=0, gets NULL, and behaves like a map that is
 * simply always empty --- which looks like a working feature and is not.
 */
#ifndef LS_MAP_GLUE_H
#define LS_MAP_GLUE_H

#include "ls_map.h"
#include <stdatomic.h>
#include <stdio.h>
#include <sys/mman.h>
#include "ls_tp.h"
#include "ubpf.h"
#include <fcntl.h>
#include <stdlib.h>   /* strtoull, for the /proc/self/maps parse */
#include <time.h>
#include <unistd.h>

/*
 * SHAPE IS GLOBAL, STORAGE IS PER THREAD, and the split is forced rather than
 * chosen. g_slots in ls_vm.c is a plain process-global, so one VM is shared by
 * every TMM thread --- but relocation runs ONCE, on the loader thread, when the
 * ELF is loaded. If the map set were purely thread-local, the loader thread would
 * get the maps and every data-plane thread would find none: lookups return NULL
 * forever and the feature looks like a map that is always empty.
 *
 * So relocation records only the SHAPE in a process-global table, and each thread
 * allocates its own STORAGE from those shapes the first time a helper runs on it.
 * Threads never share a table, so there is still no locking on the hot path.
 */
/* ONE TU DEFINES THESE, EVERY OTHER TU SEES EXTERNS. They were `static`, which
 * in a header means each including TU gets its OWN copy --- the shapes written by
 * relocation would be invisible to a helper compiled elsewhere. That never bit us
 * only because exactly one file happened to include this header; the install
 * function below means two now do. The owner defines LS_MAP_GLUE_IMPL before
 * including (ls_vm_load.c). If a second file ever does, the link fails on a
 * duplicate symbol --- loudly, at build time, which is the whole reason to prefer
 * extern here over a comment asking people to be careful. */
/*
 * IDENTITY IS THE SYMBOL NAME, NOT THE SHAPE --- and that is a fix, not a
 * preference. This table used to dedup on (key_size, value_size, max_entries)
 * alone, which is correct WITHIN one program (clang emits one relocation per
 * reference, so the same map arrives several times) and wrong ACROSS programs,
 * because g_ls_shapes is process-global and never scoped by slot. Two unrelated
 * programs each declaring a 4-byte-key/8-byte-value/64-entry map resolved to the
 * SAME index and therefore the same per-thread storage: each saw the other's
 * counts as its own. Nothing reported it --- shared state looks exactly like a
 * program whose counters are running a little high.
 *
 * Keying on the name makes both behaviours explicit and separates them:
 *
 *   same name, same shape        -> SHARE the index. Deliberate, and it is what
 *                                   lets a timer program read the counters an
 *                                   entry-armed program is accumulating.
 *   same name, different shape   -> REFUSE. Two programs disagreeing about a
 *                                   shared map's layout is the one case where
 *                                   sharing corrupts, so it must not resolve.
 *   different name               -> a NEW index, i.e. private storage.
 *
 * uBPF already hands us symbol_name; the old code took it only to print it.
 */
#define LS_MAP_NAME_MAX 32u

#ifdef LS_MAP_GLUE_IMPL
struct ls_map_def  g_ls_shapes[LS_MAP_MAX];
char               g_ls_names[LS_MAP_MAX][LS_MAP_NAME_MAX];
_Atomic uint32_t   g_ls_nshapes;             /* published with release ordering */
#else
extern struct ls_map_def g_ls_shapes[LS_MAP_MAX];
extern char              g_ls_names[LS_MAP_MAX][LS_MAP_NAME_MAX];
extern _Atomic uint32_t  g_ls_nshapes;
#endif

/* A pointer, mmap'd on first use --- NOT a __thread object. sizeof(struct
 * ls_map_set) is ~50 KB, and putting that in thread-local storage was both a
 * large TLS demand on every TMM thread and a direct contradiction of what this
 * file claims two paragraphs up ("mmap'd", because TMM's malloc is unusable on
 * threads it did not create). The claim was right; the code was not. */
#ifdef LS_MAP_GLUE_IMPL
__thread struct ls_map_set *g_ls_maps;
__thread int                g_ls_maps_failed;
/* WHICH SLOT IS EXECUTING, set by ls_vm_call before it enters the VM.
 *
 * uBPF's external_function_t is five uint64_t and NO context parameter --- ubpf.h warns
 * that a sixth will not match the typedef --- so a helper cannot be told which slot
 * invoked it. A thread-local is both simpler and cheaper than threading a context
 * through every call, and it is correct for the same reason the map tables are
 * per-thread: TMM is core-pinned and run-to-completion, so exactly one program is
 * executing on this thread at any instant.
 *
 * -1 when no program is running, so a helper reached from anywhere else refuses. */
__thread int                g_ls_cur_slot = -1;
#else
extern __thread struct ls_map_set *g_ls_maps;
extern __thread int                g_ls_maps_failed;
extern __thread int                g_ls_cur_slot;
#endif

/* Lazily bring this thread's storage up to the recorded shapes. Idempotent, and
 * cheap after the first call: a pointer test. */
static inline struct ls_map_set *
ls_map_current(void)
{
    uint32_t n, i;
    void *p;

    if (g_ls_maps_failed)
        return 0;                     /* tried once, failed --- do not retry on
                                       * the hot path, and do not leak a mapping
                                       * per invocation */

    /* CATCH UP ON SHAPES ADDED SINCE THIS THREAD INITIALISED, and note why this
     * is not merely tidiness. Shapes are recorded at LOAD time and indices are
     * global; storage is built per thread on FIRST USE. So loading a second
     * program mid-life gives it a higher index than any thread has storage for,
     * and ls_map_get() returns NULL for it --- every lookup misses, and the
     * program behaves exactly like one whose counter never reaches its threshold.
     *
     * Observed: rate_watch worked at idx 0 on a fresh pod and silently never
     * worked at idx 1 after map_selftest had claimed idx 0. "Works on the first
     * program loaded, never on the second" is a bad failure to leave in place. */
    if (g_ls_maps != 0) {
        n = atomic_load_explicit(&g_ls_nshapes, memory_order_acquire);
        for (i = g_ls_maps->n; i < n; i++) {
            if (ls_map_create(g_ls_maps, &g_ls_shapes[i]) < 0)
                return g_ls_maps;     /* table full --- existing maps still work */
        }
        return g_ls_maps;
    }

    /* ACQUIRE, paired with the release store in ls_map_reloc. Relocation runs on
     * the LOADER thread; without the pairing a data-plane thread on another core
     * has no guarantee of seeing either the count or the shapes it indexes, and
     * the failure is silent --- every lookup misses and the feature looks like a
     * map that is simply always empty. Same class as ls_vm_reload publishing vm
     * without jit_fn. */
    n = atomic_load_explicit(&g_ls_nshapes, memory_order_acquire);
    if (n == 0)
        return 0;                     /* no maps declared --- nothing to build */

    p = mmap(0, sizeof(struct ls_map_set), PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        g_ls_maps_failed = 1;
        return 0;
    }
    memset(p, 0, sizeof(struct ls_map_set));

    for (i = 0; i < n; i++) {
        if (ls_map_create((struct ls_map_set *)p, &g_ls_shapes[i]) < 0) {
            munmap(p, sizeof(struct ls_map_set));
            g_ls_maps_failed = 1;     /* a shape we cannot honour --- fail safe */
            return 0;
        }
    }
    g_ls_maps = (struct ls_map_set *)p;
    return g_ls_maps;
}


/*
 * uBPF hands us the maps section and the symbol's offset within it. We read the
 * descriptor clang wrote there, check we can honour it, create the map, and
 * return the INDEX to plant in the instruction.
 *
 * Returning an index rather than a pointer is the security boundary: a program
 * never holds or supplies a host address, so validating a map reference later is
 * an integer range check and there is no forged-pointer case at all. Real BPF
 * hands programs an fd and does this work in the kernel; we get a stronger
 * arrangement for free because uBPF left relocation to the embedder.
 *
 * On refusal we return a deliberately out-of-range value. The helper's range
 * check then rejects it, so a descriptor we cannot honour yields a program whose
 * map calls all fail --- rather than one silently wired to the wrong shape, which
 * is what clamping would produce.
 */
static inline uint64_t
ls_map_reloc(void *ctx, const uint8_t *data, uint64_t data_size,
             const char *symbol_name, uint64_t symbol_offset, uint64_t symbol_size)
{
    struct ls_map_def d;
    int idx;

    (void)ctx;
    if (data == 0)
        return (uint64_t)LS_MAP_MAX + 1u;
    if (symbol_offset + sizeof d > data_size || symbol_size < sizeof d)
        return (uint64_t)LS_MAP_MAX + 1u;   /* truncated descriptor --- refuse */

    memcpy(&d, data + symbol_offset, sizeof d);

    /* An unnamed map cannot be identified, and identity is what decides whether
     * storage is shared or private. Refuse rather than guess: a wrong guess in
     * either direction is silent. */
    if (symbol_name == 0 || symbol_name[0] == '\0')
        return (uint64_t)LS_MAP_MAX + 1u;
    if (strnlen(symbol_name, LS_MAP_NAME_MAX) >= LS_MAP_NAME_MAX)
        return (uint64_t)LS_MAP_MAX + 1u;   /* would not round-trip --- refuse */

    /* Already recorded under this NAME? clang emits one relocation per REFERENCE,
     * so the same map arrives several times --- three, in the experiment program.
     * Recording one shape per reference would exhaust the table and, worse, give
     * two references to the same declared map separate storage.
     *
     * A name match with a DIFFERENT shape is refused, not shared: the two
     * programs disagree about the layout of memory they would both write. */
    {
        uint32_t i, have = atomic_load_explicit(&g_ls_nshapes, memory_order_relaxed);
        for (i = 0; i < have; i++) {
            if (strncmp(g_ls_names[i], symbol_name, LS_MAP_NAME_MAX) != 0)
                continue;
            if (g_ls_shapes[i].key_size   == d.key_size &&
                g_ls_shapes[i].value_size == d.value_size &&
                g_ls_shapes[i].max_entries == d.max_entries)
                return (uint64_t)i;         /* deliberate share */
            fprintf(stderr, "ls_map: REFUSED %s --- shape disagrees with the "
                            "map already registered under that name "
                            "(have key=%u val=%u max=%u, asked key=%u val=%u max=%u)\n",
                    symbol_name,
                    g_ls_shapes[i].key_size, g_ls_shapes[i].value_size,
                    g_ls_shapes[i].max_entries,
                    d.key_size, d.value_size, d.max_entries);
            return (uint64_t)LS_MAP_MAX + 1u;
        }
    }

    /* Record the SHAPE only. Storage is per thread and built on first use --- see
     * ls_map_current(). Refuse here rather than at first use, so a descriptor we
     * cannot honour fails at load time where somebody is watching. */
    {
        uint32_t have = atomic_load_explicit(&g_ls_nshapes, memory_order_relaxed);
        if (!ls_map_check_descriptor(&d) || have >= LS_MAP_MAX)
            return (uint64_t)LS_MAP_MAX + 1u;
        idx = (int)have;
        g_ls_shapes[have] = d;
        /* Fill the shape AND THE NAME before publishing the count: a reader that
         * observes the count must be guaranteed to see the entry it indexes, and
         * the name is now part of that entry rather than a debug string. */
        memset(g_ls_names[have], 0, LS_MAP_NAME_MAX);
        memcpy(g_ls_names[have], symbol_name,
               strnlen(symbol_name, LS_MAP_NAME_MAX - 1u));
        atomic_store_explicit(&g_ls_nshapes, have + 1u, memory_order_release);
    }
    fprintf(stderr, "ls_map: reloc %s -> idx %d (key=%u val=%u max=%u)\n",
            symbol_name ? symbol_name : "?", idx,
            d.key_size, d.value_size, d.max_entries);
    return (uint64_t)idx;
}

/* uBPF permits only the ctx and the stack. This extends it to map values --- and
 * note the JIT does not bounds-check at all, so without this the interpreter and
 * the JIT disagree: the program works in production and fails in test. */
/*
 * Release every recorded shape. Called when a slot is revoked.
 *
 * Without this, shapes accumulate for the process lifetime: each load records
 * its own and LS_MAP_MAX is 4, so the fifth program loaded finds the table full
 * and its maps silently do not exist. Per-thread STORAGE is not reclaimed here
 * --- a data-plane thread may be inside a helper --- so the mapping is left and
 * the thread rebuilds from the new shapes on its next call. Bounded: it is one
 * mapping per thread, not per load.
 */
static inline void
ls_map_reset_shapes(void)
{
    /* Clear the NAMES as well. They are identity now, so a name left behind at an
     * index the next load reuses would match a map it has nothing to do with ---
     * reintroducing exactly the cross-program aliasing the name key removes. */
    memset(g_ls_names, 0, sizeof g_ls_names);
    atomic_store_explicit(&g_ls_nshapes, 0, memory_order_release);
}

/* This runs on the thread doing the access, so ls_map_current() gives that
 * thread's own storage --- which is the only storage its program can legally
 * reach. */
static inline bool
ls_map_bounds(void *ctx, uint64_t addr, uint64_t size)
{
    struct ls_map_set *s = ls_map_current();
    (void)ctx;
    return s != 0 && ls_map_addr_ok(s, addr, size) != 0;
}


/* --- the three helpers, at the ids PREVAIL already knows -----------------
 *
 * uBPF's external_function_t is FIVE uint64_t and NO context parameter --- ubpf.h
 * even warns that a 6th parameter will not match the typedef. There is a
 * dispatcher form that carries a context, but the map set is per-thread anyway,
 * so a thread-local pointer is both simpler and cheaper than threading a context
 * through every call.
 *
 * ls_map_set_current() is called once per thread when its maps are created. A
 * helper invoked on a thread that never did so finds NULL and returns failure ---
 * which is the safe direction: no map, no state, program falls through.
 */


static inline uint64_t
ls_h_map_lookup(uint64_t map, uint64_t key, uint64_t a, uint64_t b, uint64_t c)
{
    struct ls_map *m = ls_map_get(ls_map_current(), map);
    (void)a; (void)b; (void)c;
    if (m == 0 || key == 0)
        return 0;
    return (uint64_t)(uintptr_t)ls_map_lookup(m, (const uint8_t *)(uintptr_t)key);
}

static inline uint64_t
ls_h_map_update(uint64_t map, uint64_t key, uint64_t val, uint64_t flags, uint64_t c)
{
    struct ls_map *m = ls_map_get(ls_map_current(), map);
    (void)flags; (void)c;
    if (m == 0 || key == 0 || val == 0)
        return (uint64_t)-1;
    return (uint64_t)ls_map_update(m, (const uint8_t *)(uintptr_t)key,
                                   (const uint8_t *)(uintptr_t)val);
}

static inline uint64_t
ls_h_map_delete(uint64_t map, uint64_t key, uint64_t a, uint64_t b, uint64_t c)
{
    struct ls_map *m = ls_map_get(ls_map_current(), map);
    (void)a; (void)b; (void)c;
    if (m == 0 || key == 0)
        return (uint64_t)-1;
    return (uint64_t)ls_map_delete(m, (const uint8_t *)(uintptr_t)key);
}

/* --- readable-range cache, for bpf_probe_read ----------------------------
 *
 * WHY A RANGE CHECK AND NOT A FAULT HANDLER. bpf_probe_read must return an ERROR for a bad
 * address, never crash. The kernel gets that from its page-fault handler plus a fixup
 * table. Userspace has three options and only one of them is affordable on a poll loop:
 *
 *   range-check against cached mappings   two compares. Catches NULL, wild pointers and
 *                                         unmapped addresses --- the whole common case.
 *   process_vm_readv on self              a syscall per read. Catches everything, and is
 *                                         far too slow per invocation.
 *   SIGSEGV handler + siglongjmp          catches everything, but async-signal-safety
 *                                         inside run-to-completion, and the handler is
 *                                         PROCESS-WIDE so it collides with TMM's own crash
 *                                         handling. Not a trade to make quietly.
 *
 * So: range check. STATE THE LIMIT PLAINLY --- it does not catch a pointer that is mapped
 * but wrong. Neither does a hand-written ctx builder, which dereferences on trust today, so
 * this is not a regression; it is a bound where there was none.
 *
 * PER THREAD, like the map storage, for the same reason: no locking on the hot path. Built
 * on first use from /proc/self/maps, and REFRESHED ONCE on a miss before refusing, because
 * TMM mmaps after init (the per-thread map tables are themselves an example) and a stale
 * snapshot would refuse a legitimate read forever.
 */
#define LS_RANGES_MAX 64u

struct ls_range { uint64_t lo, hi; };

struct ls_ranges {
    struct ls_range r[LS_RANGES_MAX];
    uint32_t n;
};

#ifdef LS_MAP_GLUE_IMPL
__thread struct ls_ranges *g_ls_ranges;
__thread int               g_ls_ranges_failed;
#else
extern __thread struct ls_ranges *g_ls_ranges;
extern __thread int               g_ls_ranges_failed;
#endif

/* Parse /proc/self/maps into the readable ranges.
 *
 * Deliberately ignores any mapping without 'r' --- a write-only or guard mapping is not
 * somewhere a program may read from. Uses stdio because this runs ONCE PER THREAD at first
 * use, off the hot path; the per-invocation cost is the two compares in ls_addr_readable.
 */
static inline int
ls_ranges_load(struct ls_ranges *rs)
{
    FILE *f;
    char line[512];

    rs->n = 0;
    f = fopen("/proc/self/maps", "r");
    if (f == 0)
        return -1;
    while (rs->n < LS_RANGES_MAX && fgets(line, (int)sizeof line, f) != 0) {
        char *p = line, *q;
        uint64_t lo, hi;

        lo = strtoull(p, &q, 16);
        if (q == p || *q != '-')
            continue;
        p = q + 1;
        hi = strtoull(p, &q, 16);
        if (q == p || hi <= lo)
            continue;
        while (*q == ' ')
            q++;
        if (*q != 'r')                 /* not readable --- not our business */
            continue;
        /* Merge with the previous range when they abut. /proc/self/maps splits on permission
         * and backing changes, so a heap can appear as several adjacent readable entries and
         * a 64-slot table would otherwise fill on a large process. */
        if (rs->n > 0 && rs->r[rs->n - 1].hi == lo) {
            rs->r[rs->n - 1].hi = hi;
        } else {
            rs->r[rs->n].lo = lo;
            rs->r[rs->n].hi = hi;
            rs->n++;
        }
    }
    fclose(f);
    return rs->n ? 0 : -1;
}

/* This thread's ranges, built on first use. Returns 0 on failure, and remembers the
 * failure so a broken /proc is not retried on every invocation. */
static inline struct ls_ranges *
ls_ranges_current(int refresh)
{
    if (g_ls_ranges_failed && !refresh)
        return 0;
    if (g_ls_ranges == 0) {
        void *m = mmap(0, sizeof(struct ls_ranges), PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) {
            g_ls_ranges_failed = 1;
            return 0;
        }
        g_ls_ranges = (struct ls_ranges *)m;
        refresh = 1;
    }
    if (refresh) {
        if (ls_ranges_load(g_ls_ranges) != 0) {
            g_ls_ranges_failed = 1;
            return 0;
        }
        g_ls_ranges_failed = 0;
    }
    return g_ls_ranges;
}

/* Is [addr, addr+size) entirely inside ONE readable mapping?
 *
 * One mapping, not several: a read spanning two adjacent mappings is legal in principle and
 * is far more likely to be a pointer that walked off the end of something. Refusing it costs
 * a caller nothing real and removes a whole class of accident.
 *
 * On a miss the snapshot is REFRESHED ONCE and retried, because TMM mmaps after init --- the
 * per-thread map tables are themselves an example --- and a stale snapshot would refuse a
 * legitimate read forever.
 */
static inline int
ls_addr_readable(uint64_t addr, uint64_t size)
{
    int attempt;

    if (size == 0 || addr == 0)
        return 0;
    if (addr + size < addr)                 /* wrap --- refuse before doing arithmetic */
        return 0;

    for (attempt = 0; attempt < 2; attempt++) {
        struct ls_ranges *rs = ls_ranges_current(attempt);   /* 2nd pass refreshes */
        uint32_t i;
        if (rs == 0)
            return 0;
        for (i = 0; i < rs->n; i++) {
            if (addr >= rs->r[i].lo && addr + size <= rs->r[i].hi)
                return 1;
        }
    }
    return 0;
}

/* --- bpf_ktime_get_ns, helper id 5 ---------------------------------------
 *
 * WHY A CLOCK IS THE SINGLE MOST USEFUL ADDITION. Without one a program cannot know what
 * time it is, so it cannot express "N per second", any rate limit, or any decay. That is
 * why rate_watch's threshold means "this site fired more than 5 times EVER" rather than
 * recently --- the counter never resets, so safe_returns answers a question nobody asked.
 *
 * CLOCK_MONOTONIC, NOT CLOCK_REALTIME, and the difference matters. The ring record's
 * ts_ns is REALTIME because a feed has to correlate with wall-clock logs. A program doing
 * rate limiting must NOT be affected by a clock step: on a REALTIME jump backwards every
 * interval computation would go negative and every limiter would open. Two clocks for two
 * jobs, deliberately, and a program comparing its own timestamps against a record's ts_ns
 * would be comparing different clocks --- which is why programs get no access to ts_ns.
 *
 * Resolves through the vDSO, so no syscall. It is still a read on the hot path and the
 * per-call cost of it is UNMEASURED, like everything else on this path.
 */
static inline uint64_t
ls_h_ktime_get_ns(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    struct timespec ts;
    (void)a; (void)b; (void)c; (void)d; (void)e;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;      /* 0 is safe: a program comparing against it sees no elapsed time */
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* --- bpf_ringbuf_output, helper id 130 -----------------------------------
 *
 * PROGRAM-CONTROLLED EMISSION. Until now the host published a record for every event,
 * after the program ran, so a program could not say "this one is not interesting". That
 * fixed one-record-per-event rate is what the parked timer hook existed to work around;
 * with this helper and a clock, a program does its own rate limiting and its own
 * summarising, and the timer is not needed.
 *
 * Signature is bpf_ringbuf_output(ringbuf, data, size, flags) --- id 130, which PREVAIL
 * already knows, so this costs ZERO verifier work. Verified by test 2026-08-18: a program
 * declaring a BPF_MAP_TYPE_RINGBUF map and calling id 130 passes PREVAIL unchanged.
 *
 * WHAT WE VALIDATE, AND WHAT WE CANNOT. `size` is clamped and refused above the cap. The
 * POINTER is trusted, because PREVAIL proved the program owns [data, data+size) --- and
 * that is precisely the trust uBPF's own docs/VerifiedPrograms.md warns about: "PREVAIL
 * assumes that r1 points to a valid memory region" while uBPF "doesn't enforce any
 * particular context layout" and "memory safety depends on the program". The interpreter
 * would catch a bad pointer through the bounds callback; THE JIT DOES NOT CONSULT IT, and
 * the lab runs the JIT. So the real control here is signature verification of the program
 * (scope item 4, unbuilt), not this function. Stated rather than implied.
 */
#define LS_RB_MAX_RECORD 256u   /* the drain reads into a 512-byte buffer; stay well
                                 * under it, and cap what one program can push per
                                 * invocation so a hot hook cannot flood the ring in a
                                 * single call */

static inline uint64_t
ls_h_perf_event_output(uint64_t ctx, uint64_t map, uint64_t flags, uint64_t data,
                       uint64_t size)
{
    struct ls_map *m = ls_map_get(ls_map_current(), map);

    /* ARGUMENT ORDER IS bpf_perf_event_output(ctx, map, flags, data, size). The map is
     * arg 1 and the payload is args 3 and 4 --- NOT bpf_ringbuf_output's
     * (map, data, size, flags), which this used before id 130 turned out to be outside
     * uBPF's table. Getting the order wrong would read the ctx pointer as a map index. */
    (void)ctx; (void)flags;

    /* Refuse, never clamp. A silently truncated record decodes as a short one and a
     * consumer cannot tell it from a program that meant to emit that much. */
    if (m == 0 || !m->is_ring)
        return (uint64_t)-1;          /* not an event-output map */
    if (data == 0 || size == 0 || size > LS_RB_MAX_RECORD)
        return (uint64_t)-1;
    if (g_ls_cur_slot < 0)
        return (uint64_t)-1;          /* reached from outside a program run */

    return (uint64_t)(int64_t)ls_tp_publish_raw(g_ls_cur_slot,
                                                (const void *)(uintptr_t)data,
                                                (unsigned long)size);
}

/* --- bpf_probe_read, helper id 4 -----------------------------------------
 *
 * WHY THIS IS THE MOST STRUCTURALLY IMPORTANT HELPER IN THE SET. A verified program cannot
 * chase a pointer --- PREVAIL refuses it --- so until now the HOST had to dereference and
 * hand the program flat scalars. That host code is a per-hook ctx builder written in C and
 * COMPILED INTO TMM, which means a hook with a new argument shape costs a rebuild.
 *
 * With this helper the program chases pointers itself, and the generic five-register ctx
 * covers arbitrary hooks. A new hook shape becomes a NEW PROGRAM rather than a new build:
 * minutes instead of a build cycle. That is the difference between "we can instrument
 * anything, given a rebuild" and "we can instrument anything, now".
 *
 * PREVAIL admits id 4 with every gate on --- verified before this was written, not after.
 *
 * WHAT IS AND IS NOT GUARANTEED, stated because the whole value depends on it:
 *
 *   src   RANGE-CHECKED against this thread's readable mappings. NULL, unmapped and wild
 *         pointers are refused with -1 rather than faulting. A pointer that is mapped but
 *         semantically wrong is NOT caught --- and neither is it by a hand-written ctx
 *         builder, which dereferences on trust today. This is a bound where there was none.
 *   size  capped. A program cannot ask for an unbounded copy.
 *   dst   TRUSTED, because PREVAIL proved the program owns it. Same trust the event-output
 *         helper takes, and the same reason it is the signing gate (scope item 4) that
 *         really underwrites this rather than any check here.
 *
 * The kernel's version of this helper is backed by the page-fault handler and a fixup table.
 * Ours is a range check, because the userspace alternatives are a syscall per read (far too
 * slow on a poll loop) or a process-wide SIGSEGV handler with siglongjmp (async-signal-safety
 * inside run-to-completion, colliding with TMM's own crash handling). The range check is the
 * affordable 95%, and saying which 5% it misses is the point of this comment.
 */
#define LS_PROBE_READ_MAX 256u

static inline uint64_t
ls_h_probe_read(uint64_t dst, uint64_t size, uint64_t src, uint64_t d, uint64_t e)
{
    (void)d; (void)e;

    if (dst == 0 || src == 0 || size == 0)
        return (uint64_t)-1;
    if (size > LS_PROBE_READ_MAX)
        return (uint64_t)-1;          /* refuse, never clamp --- a short read is
                                       * indistinguishable from a program that meant it */
    if (!ls_addr_readable(src, size))
        return (uint64_t)-1;

    memcpy((void *)(uintptr_t)dst, (const void *)(uintptr_t)src, (size_t)size);
    return 0;
}

/* Assert the helper signatures really match uBPF's, so a future edit that adds a
 * parameter fails the build rather than corrupting arguments at run time. */
static inline void
ls_map_glue_abi_check(void)
{
    external_function_t f;
    f = (external_function_t)ls_h_map_lookup; (void)f;
    f = (external_function_t)ls_h_map_update; (void)f;
    f = (external_function_t)ls_h_map_delete; (void)f;
    f = (external_function_t)ls_h_ktime_get_ns; (void)f;
    f = (external_function_t)ls_h_perf_event_output; (void)f;
    f = (external_function_t)ls_h_probe_read; (void)f;
}

/*
 * THE ONE CALL. Every VM that will run a program with maps goes through here,
 * before ubpf_load_elf_ex --- see the ordering note in the banner. Returns 0, or
 * -1 with a reason on stderr.
 *
 * Registration is all-or-nothing on purpose. A VM with the relocation callback
 * but no bounds check would resolve map indices and then refuse every read of a
 * value; a VM with helpers but no relocation would hand every helper map=0. Both
 * produce a program that loads, verifies and runs while its maps do nothing. So a
 * partial install is treated as a failed install.
 */
static inline int
ls_map_glue_install(struct ubpf_vm *vm)
{
    if (vm == 0)
        return -1;

    /* Order: relocation first, because ubpf_load_elf_ex walks the maps section
     * and consults it there. Registered afterwards it is simply never asked. */
    if (ubpf_register_data_relocation(vm, 0, ls_map_reloc) != 0) {
        fprintf(stderr, "ls_map: relocation callback refused\n");
        return -1;
    }
    if (ubpf_register_data_bounds_check(vm, 0, ls_map_bounds) != 0) {
        fprintf(stderr, "ls_map: bounds callback refused\n");
        return -1;
    }

    /* ids 1/2/3 with the standard names and semantics, which is what lets
     * PREVAIL verify these programs with no platform work at all. */
    if (ubpf_register(vm, 1, "bpf_map_lookup_elem",
                      (external_function_t)ls_h_map_lookup) != 0 ||
        ubpf_register(vm, 2, "bpf_map_update_elem",
                      (external_function_t)ls_h_map_update) != 0 ||
        ubpf_register(vm, 3, "bpf_map_delete_elem",
                      (external_function_t)ls_h_map_delete) != 0) {
        fprintf(stderr, "ls_map: helper registration refused\n");
        return -1;
    }

    /* ids 5 and 130, again with the standard names and semantics so PREVAIL needs no
     * platform work. All-or-nothing with the three above: a VM that resolved a ringbuf
     * map and then had no helper to emit through would give a program that verifies,
     * runs, and silently drops everything it tried to publish. */
    /* EVERY ID MUST BE INSIDE uBPF'S TABLE, asserted at COMPILE time. ubpf_register
     * refuses idx >= UBPF_MAX_EXT_FUNCS (64 by default, ubpf.h:72) and returns -1, which
     * all-or-nothing turns into a total install failure. An image shipped that way on
     * 2026-08-18: bpf_ringbuf_output's id is 130, so NO helper registered at all, every
     * program load was refused and even the built-in shield never armed. Loud, which is
     * what all-or-nothing is for --- but a build failure is better than loud. */
    _Static_assert(4  < UBPF_MAX_EXT_FUNCS, "bpf_probe_read id outside uBPF's table");
    _Static_assert(5  < UBPF_MAX_EXT_FUNCS, "bpf_ktime_get_ns id outside uBPF's table");
    _Static_assert(25 < UBPF_MAX_EXT_FUNCS, "bpf_perf_event_output id outside the table");
    _Static_assert(1  < UBPF_MAX_EXT_FUNCS && 2 < UBPF_MAX_EXT_FUNCS
                   && 3 < UBPF_MAX_EXT_FUNCS, "map helper ids outside uBPF's table");

    if (ubpf_register(vm, 4, "bpf_probe_read",
                      (external_function_t)ls_h_probe_read) != 0 ||
        ubpf_register(vm, 5, "bpf_ktime_get_ns",
                      (external_function_t)ls_h_ktime_get_ns) != 0 ||
        ubpf_register(vm, 25, "bpf_perf_event_output",
                      (external_function_t)ls_h_perf_event_output) != 0) {
        fprintf(stderr, "ls_map: probe-read/clock/event-output registration refused\n");
        return -1;
    }

    ls_map_glue_abi_check();     /* compile-time signature pin, no run cost */
    return 0;
}

#endif /* LS_MAP_GLUE_H */
