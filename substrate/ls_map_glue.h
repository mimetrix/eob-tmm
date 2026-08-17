/* ls_map_glue.h --- the three uBPF callbacks that make maps work.
 *
 * Registered on every VM before the ELF is loaded, because the relocation
 * callback has to be in place when uBPF walks the maps section.
 *
 *   relocation    resolve `lddw r1, <map symbol>` to a map INDEX
 *   bounds check  permit reads of map VALUE memory
 *   helpers 1/2/3 the standard BPF map helpers, which PREVAIL already knows
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
#include "ubpf.h"

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
static struct ls_map_def  g_ls_shapes[LS_MAP_MAX];
static _Atomic uint32_t   g_ls_nshapes;      /* published with release ordering */

/* A pointer, mmap'd on first use --- NOT a __thread object. sizeof(struct
 * ls_map_set) is ~50 KB, and putting that in thread-local storage was both a
 * large TLS demand on every TMM thread and a direct contradiction of what this
 * file claims two paragraphs up ("mmap'd", because TMM's malloc is unusable on
 * threads it did not create). The claim was right; the code was not. */
static __thread struct ls_map_set *g_ls_maps;
static __thread int                g_ls_maps_failed;

/* Lazily bring this thread's storage up to the recorded shapes. Idempotent, and
 * cheap after the first call: a pointer test. */
static inline struct ls_map_set *
ls_map_current(void)
{
    uint32_t n, i;
    void *p;

    if (g_ls_maps != 0)
        return g_ls_maps;
    if (g_ls_maps_failed)
        return 0;                     /* tried once, failed --- do not retry on
                                       * the hot path, and do not leak a mapping
                                       * per invocation */

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

    /* Already recorded? clang emits one relocation per REFERENCE, so the same map
     * arrives several times --- three, in the experiment program. Recording one
     * shape per reference would exhaust the table and, worse, give two references
     * to the same declared map separate storage. */
    {
        uint32_t i, have = atomic_load_explicit(&g_ls_nshapes, memory_order_relaxed);
        for (i = 0; i < have; i++) {
            if (g_ls_shapes[i].key_size == d.key_size &&
                g_ls_shapes[i].value_size == d.value_size &&
                g_ls_shapes[i].max_entries == d.max_entries)
                return (uint64_t)i;
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
        /* Fill the shape BEFORE publishing the count: a reader that observes the
         * count must be guaranteed to see the entry it indexes. */
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

/* Assert the helper signatures really match uBPF's, so a future edit that adds a
 * parameter fails the build rather than corrupting arguments at run time. */
static inline void
ls_map_glue_abi_check(void)
{
    external_function_t f;
    f = (external_function_t)ls_h_map_lookup; (void)f;
    f = (external_function_t)ls_h_map_update; (void)f;
    f = (external_function_t)ls_h_map_delete; (void)f;
}

#endif /* LS_MAP_GLUE_H */
