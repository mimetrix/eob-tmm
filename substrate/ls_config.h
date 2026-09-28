/* ls_config.h -- bounded controller input, independent of mutable hash maps.
 * Single serialized control writer; readers make ONE attempt, never spin.
 * Atomic payload words are essential: a seqlock around ordinary memcpy would
 * still be a C data race. Sequential consistency gives the copy/check protocol
 * one total order. This is deliberately conservative until measured on TMM.
 */
#ifndef LS_CONFIG_H
#define LS_CONFIG_H
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "configuration wire ABI v1 requires a little-endian host"
#endif

#define LS_CONFIG_ABI 1u
#define LS_CONFIG_SLOTS 64u
#define LS_CONFIG_ROWS 16u
#define LS_CONFIG_VALUE_SIZE 32u
#define LS_CONFIG_MAP_NAME "ls_config_v1"
#define LS_CONFIG_MAP_FLAG 128u /* BPF_F_RDONLY_PROG; host image never exposed */
#define LS_CONFIG_HANDLE_BIT (UINT64_C(1) << 63)

struct ls_config_meta {
    uint64_t revision;
    uint64_t instance;
    uint32_t schema;
    uint32_t entries;
    uint64_t reserved;
};
struct ls_config_image {
    struct ls_config_meta meta; /* array index 0; data occupy indices 1..entries */
    uint8_t rows[LS_CONFIG_ROWS][LS_CONFIG_VALUE_SIZE];
};
#define LS_CONFIG_WORDS (sizeof(struct ls_config_image) / sizeof(uint64_t))
_Static_assert(sizeof(struct ls_config_meta) == 32, "config metadata ABI");
_Static_assert(sizeof(struct ls_config_image) == 544, "config image ABI");
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2, "config requires lock-free 64-bit atomics");

/* Little-endian wire body in shield_msg.prog, CONFIG_PUBLISH only. */
struct ls_config_request {
    uint32_t abi, schema;
    uint64_t session, instance, expected_revision, revision;
    uint32_t entries, reserved;
    uint8_t program_sha256[32];
    uint8_t rows[LS_CONFIG_ROWS][LS_CONFIG_VALUE_SIZE];
};
#define LS_CONFIG_REQUEST_HEADER 80u
_Static_assert(offsetof(struct ls_config_request, rows) == LS_CONFIG_REQUEST_HEADER,
               "config request ABI");

struct ls_config_slot {
    _Atomic uint64_t sequence;
    _Atomic uint64_t words[LS_CONFIG_WORDS];
    /* Control-plane only. Never read by a program or a data-path thread. */
    struct ls_config_meta current;
    uint8_t program_sha256[32];
};
struct ls_config_store {
    uint64_t session, next_instance; /* serialized load/publish control path */
    uint64_t loading;               /* relocation cookie for VM being prepared */
    int load_error;
    struct ls_config_slot slots[LS_CONFIG_SLOTS];
};
struct ls_config_view {
    int active, attempted, available;
    unsigned slot;
    uint64_t handle;
    struct ls_config_image image; /* program-writable, invocation-private copy */
};

static inline uint64_t
ls_config_new_instance(struct ls_config_store *s, unsigned slot)
{
    if (slot >= LS_CONFIG_SLOTS || s->next_instance >= (LS_CONFIG_HANDLE_BIT >> 6) - 1)
        return 0;
    return LS_CONFIG_HANDLE_BIT | (++s->next_instance << 6) | slot;
}

static inline int
ls_config_write(struct ls_config_slot *s, const struct ls_config_image *image)
{
    uint64_t seq = atomic_load(&s->sequence);
    if ((seq & 1) || seq > UINT64_MAX - 2)
        return -1;
    atomic_store(&s->sequence, seq + 1);
    for (size_t i = 0; i < LS_CONFIG_WORDS; i++) {
        uint64_t word;
        memcpy(&word, (const uint8_t *)image + i * 8, 8);
        atomic_store(&s->words[i], word);
    }
    atomic_store(&s->sequence, seq + 2);
    s->current = image->meta;
    return 0;
}

/* Called after successful load; token was embedded in that VM's map relocation.
 * In-flight old bytecode retains its old token, so cannot read the new image. */
static inline int
ls_config_bind(struct ls_config_store *s, unsigned slot, uint64_t instance,
               const uint8_t sha[32])
{
    struct ls_config_image empty = {0};
    if (slot >= LS_CONFIG_SLOTS || !(instance & LS_CONFIG_HANDLE_BIT) ||
        (instance & 63) != slot)
        return -1;
    empty.meta.instance = instance;
    if (ls_config_write(&s->slots[slot], &empty) != 0)
        return -1;
    memcpy(s->slots[slot].program_sha256, sha, 32);
    return 0;
}

static inline int
ls_config_revoke(struct ls_config_store *s, unsigned slot)
{
    struct ls_config_image empty = {0};
    if (slot >= LS_CONFIG_SLOTS)
        return -1;
    return ls_config_write(&s->slots[slot], &empty);
}

/* NULL means published. Errors never modify the previous image. A zero-row
 * publication is an explicit empty configuration, not a reset of revision. */
static inline const char *
ls_config_publish(struct ls_config_store *s, unsigned slot, const void *body, size_t len)
{
    struct ls_config_request r = {0};
    struct ls_config_image image = {0};
    if (slot >= LS_CONFIG_SLOTS || !body || len < LS_CONFIG_REQUEST_HEADER || len > sizeof r)
        return "config length or slot";
    memcpy(&r, body, len);
    if (r.abi != LS_CONFIG_ABI || r.reserved || !r.schema || r.entries > LS_CONFIG_ROWS ||
        len != LS_CONFIG_REQUEST_HEADER + r.entries * LS_CONFIG_VALUE_SIZE)
        return "config ABI, schema, reserved, or shape";
    struct ls_config_slot *dst = &s->slots[slot];
    if (!s->session || r.session != s->session)
        return "config session mismatch";
    if (!dst->current.instance || r.instance != dst->current.instance ||
        memcmp(r.program_sha256, dst->program_sha256, 32))
        return "config program instance/hash mismatch";
    if (r.expected_revision != dst->current.revision || r.revision <= r.expected_revision)
        return "config revision conflict";
    image.meta.instance = r.instance;
    image.meta.revision = r.revision;
    image.meta.schema = r.schema;
    image.meta.entries = r.entries;
    memcpy(image.rows, r.rows, r.entries * LS_CONFIG_VALUE_SIZE);
    return ls_config_write(dst, &image) == 0 ? NULL : "config sequence exhausted";
}

static inline void
ls_config_begin(struct ls_config_view *v, unsigned slot)
{
    v->active = 1;
    v->slot = slot;
    v->attempted = v->available = 0;
    v->handle = 0;
}

static inline void *
ls_config_lookup(struct ls_config_store *s, struct ls_config_view *v,
                 uint64_t handle, uint32_t key)
{
    if (!v->active || !(handle & LS_CONFIG_HANDLE_BIT) ||
        v->slot >= LS_CONFIG_SLOTS || (handle & 63) != v->slot || key > LS_CONFIG_ROWS)
        return NULL;
    if (!v->attempted) {
        v->attempted = 1;
        v->handle = handle;
        struct ls_config_slot *src = &s->slots[v->slot];
        uint64_t before = atomic_load(&src->sequence);
        if (before & 1)
            return NULL;
        for (size_t i = 0; i < LS_CONFIG_WORDS; i++) {
            uint64_t word = atomic_load(&src->words[i]);
            memcpy((uint8_t *)&v->image + i * 8, &word, 8);
        }
        if (before != atomic_load(&src->sequence) || v->image.meta.instance != handle ||
            !v->image.meta.revision)
            return NULL;
        v->available = 1;
    }
    if (!v->available || handle != v->handle || key > v->image.meta.entries)
        return NULL;
    return (uint8_t *)&v->image + key * LS_CONFIG_VALUE_SIZE;
}

static inline int
ls_config_addr_ok(const struct ls_config_view *v, uint64_t addr, uint64_t size)
{
    uint64_t base = (uint64_t)(uintptr_t)&v->image;
    /* Use the fixed allocation bound, not program-writable metadata. */
    return v->active && v->available && addr >= base && addr - base < sizeof v->image &&
           size <= LS_CONFIG_VALUE_SIZE - ((addr - base) % LS_CONFIG_VALUE_SIZE);
}
#endif
