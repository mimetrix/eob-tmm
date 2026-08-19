/* PROOF THAT A HOOK NEEDS NO ctx BUILDER.
 *
 * Every other program here is handed a typed record that host-side C assembled --- and that C
 * is compiled into TMM, so a hook with a new argument shape costs a REBUILD. This program is
 * handed the generic five-register context instead, which the dispatcher provides for any slot
 * with no typed builder, and does its own dereferencing through bpf_probe_read.
 *
 * Armed on rst_why in a generic slot, the register context is:
 *
 *     arg[0]  union uflow *uf
 *     arg[1]  const char *file      <- __FILE__, a pointer into TMM's rodata
 *     arg[2]  unsigned lineno
 *     arg[3]  err_t err
 *     arg[4]  int reason
 *
 * arg[1] is a POINTER, and a verified program cannot dereference one --- that is the whole
 * reason ctx builders exist. bpf_probe_read can, because the host range-checks the address
 * against the process's readable mappings and returns -1 rather than faulting.
 *
 * So this recovers the filename from a hook it was never built for: the same information the
 * typed reset record carries, with no host-side code and therefore no rebuild.
 *
 * WHAT IT DOES NOT GET, so the comparison is honest: the generic context carries five
 * registers, and rst_why's sixth argument is the cause string. A typed builder sees all six,
 * because the trampoline saves all six. So probe_read removes the REBUILD, not every reason to
 * write a builder --- a builder still buys the sixth argument, and derivations like
 * UFLOW_COOKIE that no generator could invent.
 */
typedef unsigned int  __u32;
typedef unsigned long long __u64;

struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
#define BPF_MAP_TYPE_HASH 1

struct bpf_map_def probe_by_file __attribute__((section("maps"), used)) = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 64,
};

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;
static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

/* The generic register context --- no per-hook type, no host builder. */
struct ls_ctx_generic { __u64 arg[5]; };

__attribute__((section("fentry/rst_why"), used))
__u64
shield(struct ls_ctx_generic *c)
{
    char name[16];
    __u32 key;
    __u64 *n, v = 1;
    int i;

    /* Chase arg[1] --- TMM's __FILE__ pointer --- into our own stack. A bad address returns
     * -1 and we fall through rather than fault. */
    for (i = 0; i < 16; i++)
        name[i] = 0;
    if (bpf_probe_read(name, sizeof name, (const void *)c->arg[1]) != 0)
        return 0ull;

    /* Fold the first bytes plus the line number into a key. Bounded and fully unrolled: no
     * backedge for the verifier to bound, and no dependence on the string's length, which
     * comes from TMM rather than from us. */
    key = (__u32)c->arg[2]
        ^ ((__u32)(unsigned char)name[0] << 8)
        ^ ((__u32)(unsigned char)name[1] << 16)
        ^ ((__u32)(unsigned char)name[2] << 24);

    n = bpf_map_lookup_elem(&probe_by_file, &key);
    if (n)
        v = *n + 1;
    bpf_map_update_elem(&probe_by_file, &key, &v, 0);
    return 0ull;                    /* observation only --- always fall through */
}
