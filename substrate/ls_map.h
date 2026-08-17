/* ls_map.h --- state that survives between program invocations.
 *
 * WHY THIS IS THE UNLOCK. Until now a program saw one invocation, answered yes or
 * no, and forgot everything. The only question expressible was "is this one input
 * bad?". With a map it can ask "has this client done this forty times in a
 * minute?" --- which is what most real abuse looks like, and what TMM's tmstat
 * counters cannot answer because they hold totals with no link back to the
 * request that caused them.
 *
 * THREE THINGS THAT MADE THIS CHEAPER THAN EXPECTED, each an assumption that was
 * wrong:
 *
 *   - PREVAIL already understands maps. A program declaring a standard
 *     SEC("maps") hash and calling helpers 1/2/3 verifies UNCHANGED, with every
 *     gate on (substrate/shields/exp/map_probe.bpf.c). Helper ids 1/2/3 are the
 *     standard BPF map helpers and PREVAIL's linux platform knows their
 *     signatures, so implementing those ids with those semantics needs no
 *     verifier work at all.
 *   - uBPF resolves the map reference for us. clang emits `lddw r1, 0` plus an
 *     R_BPF_64_64 relocation against the map symbol, and uBPF ignores
 *     relocations --- so the helper would receive 0. But
 *     ubpf_register_data_relocation() is a callback for exactly this: uBPF hands
 *     us the maps section and the symbol offset, and we return the value to plant
 *     in the instruction.
 *   - uBPF can be taught that map memory is legal. Its bounds check permits only
 *     the ctx and the stack, so a returned value pointer would be refused;
 *     ubpf_register_data_bounds_check() extends that. Note the JIT does NOT
 *     bounds-check at all, so without this the interpreter and the JIT would
 *     disagree --- working in production and failing in test, which is the worst
 *     possible split.
 *
 * WHAT THE PROGRAM IS HANDED, AND THE SECURITY BOUNDARY. The relocation returns
 * a SMALL INDEX, not a pointer. So a program never holds or supplies a host
 * address, and validating a map reference is a range check on an integer --- there
 * is no forged-pointer case to defend against. That is stronger than real BPF's
 * arrangement and it fell out of uBPF's missing relocation step.
 *
 * PREVAIL proves the program passed *a map descriptor* and that it reads at most
 * value_size bytes of what lookup returned. It cannot prove the HOST resolves the
 * index to a map of that shape. So ls_map_check_descriptor() is the crossing
 * where the verifier's assumption meets our storage, and it is the same class of
 * check as finding O14: the verifier proved something about one artifact and the
 * runtime must be shown to agree.
 *
 * PER THREAD, FIXED SIZE, NO LOCKS. One map set per TMM thread, mmap'd at init,
 * never grown, never rehashed. Per-thread removes locking from the hot path by
 * construction, which is the same reason the egress ring is per-thread. mmap
 * rather than malloc because TMM aliases malloc to a per-core allocator whose
 * spinlock is never initialised on threads TMM did not create.
 *
 * Collision policy is EVICT, counted. A bounded table that blocks or fails on a
 * full bucket would put an attacker in control of the data path; overwriting the
 * incumbent and counting it keeps the cost fixed and the loss visible.
 */
#ifndef LS_MAP_H
#define LS_MAP_H

#include <stdint.h>
#include <string.h>

#define LS_MAP_MAX      4u      /* maps per program                     */
#define LS_MAP_ENTRIES  256u    /* power of two --- index masks cleanly  */
#define LS_MAP_KEY_MAX  16u
#define LS_MAP_VAL_MAX  32u

/* Matches struct bpf_map_def, which is what clang writes into SEC("maps") and
 * what PREVAIL parses. Read by the relocation callback. */
struct ls_map_def {
    uint32_t type, key_size, value_size, max_entries, map_flags;
};

#define LS_MAP_TYPE_HASH 1u     /* BPF_MAP_TYPE_HASH */

struct ls_map {
    uint32_t in_use;
    uint32_t key_sz, val_sz, entries;
    uint64_t hits, misses, evictions, updates;
    uint8_t  used[LS_MAP_ENTRIES];
    uint8_t  keys[LS_MAP_ENTRIES * LS_MAP_KEY_MAX];
    uint8_t  vals[LS_MAP_ENTRIES * LS_MAP_VAL_MAX];
};

struct ls_map_set {
    struct ls_map m[LS_MAP_MAX];
    uint32_t      n;
};

/* FNV-1a over the key bytes. Not cryptographic and does not need to be: the
 * table is per-thread and bounded, so the worst an attacker achieves by forcing
 * collisions is eviction of their own entries, which is already the policy. */
static inline uint32_t
ls_map_hash(const uint8_t *k, uint32_t n)
{
    uint32_t h = 2166136261u, i;
    for (i = 0; i < n; i++) {
        h ^= k[i];
        h *= 16777619u;
    }
    return h & (LS_MAP_ENTRIES - 1u);
}

/*
 * THE CROSSING. PREVAIL verified the program against the descriptor in the ELF;
 * this is where that descriptor is checked against what the host can actually
 * store. A mismatch means the verifier proved bounds for a shape we do not
 * enforce, so it is a REFUSAL, never a clamp.
 */
static inline int
ls_map_check_descriptor(const struct ls_map_def *d)
{
    if (d->type != LS_MAP_TYPE_HASH)                return 0;
    if (d->key_size == 0 || d->key_size > LS_MAP_KEY_MAX)   return 0;
    if (d->value_size == 0 || d->value_size > LS_MAP_VAL_MAX) return 0;
    if (d->max_entries == 0 || d->max_entries > LS_MAP_ENTRIES) return 0;
    return 1;
}

/* Create a map from a verified descriptor. Returns its index, or -1. */
static inline int
ls_map_create(struct ls_map_set *s, const struct ls_map_def *d)
{
    struct ls_map *m;
    if (s->n >= LS_MAP_MAX || !ls_map_check_descriptor(d))
        return -1;
    m = &s->m[s->n];
    memset(m, 0, sizeof *m);
    m->in_use  = 1;
    m->key_sz  = d->key_size;
    m->val_sz  = d->value_size;
    m->entries = d->max_entries;
    return (int)s->n++;
}

/* Resolve an index handed back by a program. THE validation --- an integer range
 * check, because the program never holds an address. */
static inline struct ls_map *
ls_map_get(struct ls_map_set *s, uint64_t idx)
{
    if (s == 0)
        return 0;           /* helper ran on a thread with no maps --- fail safe */
    if (idx >= (uint64_t)s->n)
        return 0;
    return s->m[idx].in_use ? &s->m[idx] : 0;
}

/* Linear probe from the hash, bounded by the table size --- so a lookup is O(1)
 * with a constant worst case, which is what a data path requires. */
static inline int
ls_map_slot(struct ls_map *m, const uint8_t *key, int for_insert)
{
    uint32_t h = ls_map_hash(key, m->key_sz), i, s;
    for (i = 0; i < m->entries; i++) {
        s = (h + i) & (LS_MAP_ENTRIES - 1u);
        if (s >= m->entries)
            continue;
        if (!m->used[s])
            return for_insert ? (int)s : -1;
        if (memcmp(&m->keys[s * LS_MAP_KEY_MAX], key, m->key_sz) == 0)
            return (int)s;
    }
    /* Full: evict at the hash position rather than failing. Counted by the
     * caller --- a silent eviction is indistinguishable from a miss. */
    return for_insert ? (int)(h & (LS_MAP_ENTRIES - 1u)) % (int)m->entries : -1;
}

static inline void *
ls_map_lookup(struct ls_map *m, const uint8_t *key)
{
    int s = ls_map_slot(m, key, 0);
    if (s < 0) { m->misses++; return 0; }
    m->hits++;
    return &m->vals[(uint32_t)s * LS_MAP_VAL_MAX];
}

static inline int
ls_map_update(struct ls_map *m, const uint8_t *key, const uint8_t *val)
{
    int s = ls_map_slot(m, key, 1);
    if (s < 0)
        return -1;
    if (m->used[s] && memcmp(&m->keys[(uint32_t)s * LS_MAP_KEY_MAX], key, m->key_sz) != 0)
        m->evictions++;
    memcpy(&m->keys[(uint32_t)s * LS_MAP_KEY_MAX], key, m->key_sz);
    memcpy(&m->vals[(uint32_t)s * LS_MAP_VAL_MAX], val, m->val_sz);
    m->used[s] = 1;
    m->updates++;
    return 0;
}

static inline int
ls_map_delete(struct ls_map *m, const uint8_t *key)
{
    int s = ls_map_slot(m, key, 0);
    if (s < 0)
        return -1;
    m->used[s] = 0;
    return 0;
}

/*
 * The bounds-check callback's predicate: is `addr` inside a value slot of some
 * map in this set, for `size` bytes?
 *
 * Deliberately checks against the VALUE array only. Keys and metadata are the
 * host's; a program has no business reading either, and PREVAIL never gives it a
 * pointer to them.
 */
static inline int
ls_map_addr_ok(struct ls_map_set *s, uint64_t addr, uint64_t size)
{
    uint32_t i;
    for (i = 0; i < s->n; i++) {
        struct ls_map *m = &s->m[i];
        uint64_t lo = (uint64_t)(uintptr_t)m->vals;
        uint64_t hi = lo + (uint64_t)m->entries * LS_MAP_VAL_MAX;
        if (addr < lo || addr >= hi)
            continue;
        /* Must not straddle the end of the slot it starts in --- otherwise a
         * program could read one value and the beginning of the next. */
        if (size > LS_MAP_VAL_MAX)
            return 0;
        if (((addr - lo) % LS_MAP_VAL_MAX) + size > LS_MAP_VAL_MAX)
            return 0;
        if (addr + size > hi)
            return 0;
        return 1;
    }
    return 0;
}

#endif /* LS_MAP_H */
