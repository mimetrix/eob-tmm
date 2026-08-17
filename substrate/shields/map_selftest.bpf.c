/* Does a value written to a map come back? Nothing else.
 *
 * Distinguishes two states that look identical from the counters: a working map
 * whose threshold was never reached, and a BROKEN map where every lookup returns
 * NULL. The second is the failure mode ls_map_glue.h warns about --- if the
 * relocation callback is not registered before the ELF is loaded, every `lddw`
 * holds clang's zero, every lookup misses, and a counting program looks exactly
 * like one whose count never got high enough.
 *
 * Writes a fixed key, reads it straight back, and selects only if the value
 * survived. safe_returns tracking fired means maps work. safe_returns staying at
 * zero means they do not, whatever the traffic did.
 */
typedef unsigned int __u32;
typedef unsigned long long __u64;

struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
#define BPF_MAP_TYPE_HASH 1

struct bpf_map_def probe __attribute__((section("maps"), used)) = {
    .type = BPF_MAP_TYPE_HASH, .key_size = sizeof(__u32),
    .value_size = sizeof(__u64), .max_entries = 8,
};

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;

/* 92 bytes; must match the host --- see substrate/ls_ctx_rst.h. */
struct ls_ctx_rst {
    __u32 cookie_lo, cookie_hi;      /* TMM's flow cookie; 0 = no flow */
    __u32 lineno, err, reason, file_len, cause_len;
    char  file[28];
    char  cause[36];
};
_Static_assert(sizeof(struct ls_ctx_rst) == 92, "host/program record mismatch");

__attribute__((section("fentry/rst_why"), used))
__u64
shield(struct ls_ctx_rst *c)
{
    __u32 k = 1;
    __u64 want = 0xABCDEF, *got;
    (void)c;

    bpf_map_update_elem(&probe, &k, &want, 0);
    got = bpf_map_lookup_elem(&probe, &k);
    if (got && *got == 0xABCDEF)
        return 1ull;        /* the value survived --- maps work */
    return 0ull;            /* lookup missed or came back wrong */
}
