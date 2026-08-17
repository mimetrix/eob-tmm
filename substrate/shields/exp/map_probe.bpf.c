/* EXPERIMENT: does PREVAIL verify a standard BPF map access, unchanged?
 *
 * If yes, adding maps needs NO verifier work --- only a host-side implementation
 * of helper ids 1/2/3 via ubpf_register. If no, we need a custom PREVAIL
 * platform, which is a different order of effort.
 */
typedef unsigned int __u32;
typedef unsigned long long __u64;

/* the classic SEC("maps") descriptor PREVAIL's parse_maps_section_linux reads */
struct bpf_map_def {
    __u32 type, key_size, value_size, max_entries, map_flags;
};

#define BPF_MAP_TYPE_HASH 1

struct bpf_map_def counts __attribute__((section("maps"), used)) = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 64,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;

struct ctx { __u32 a, b; };

__attribute__((section("fentry/map_probe"), used))
__u64
shield(struct ctx *c)
{
    __u32 key = c->a & 63u;
    __u64 *v = bpf_map_lookup_elem(&counts, &key);
    if (v) {
        __u64 n = *v + 1;
        bpf_map_update_elem(&counts, &key, &n, 0);
        return n > 100 ? 1u : 0u;
    }
    __u64 one = 1;
    bpf_map_update_elem(&counts, &key, &one, 0);
    return 0u;
}
