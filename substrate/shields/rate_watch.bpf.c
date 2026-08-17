/* tmm:rate --- counts per key across invocations. THE point of maps.
 *
 * Every program before this one was stateless: it saw one invocation, answered
 * yes or no, and forgot. The only expressible question was "is this one input
 * bad?". This asks a different kind of question entirely --- "how many times has
 * THIS key done this?" --- which is what most real abuse looks like and what no
 * amount of per-request inspection can see.
 *
 * It is also the thing tmstat cannot do. tmstat holds totals: 412 events this
 * interval. It has no link back to which request, or which client, produced them.
 * A map IS that link, and correlation was the one unique claim that survived
 * scrutiny of everything else we considered exposing.
 *
 * WHAT IT DOES. Keys on the reset site (file hash + line) and counts. Over
 * threshold, it selects --- so `safe_returns` becomes "how many times did some
 * single site fire more than N times", not "how many events happened". Same
 * record, same hook, a question that was previously impossible.
 *
 * THE MAP IS PER THREAD. Storage is allocated per TMM thread from a globally
 * recorded shape, so counts are per-thread and a consumer sums them. That is
 * deliberate: sharing one table across TMM's poll threads would mean locking on
 * the data path, and the whole design avoids that by construction.
 */
typedef unsigned int  __u32;
typedef unsigned long long __u64;

struct bpf_map_def {
    __u32 type, key_size, value_size, max_entries, map_flags;
};
#define BPF_MAP_TYPE_HASH 1

/* 4-byte key, 8-byte counter, 64 entries --- inside what ls_map.h can honour.
 * A descriptor the host cannot store is REFUSED at load, not clamped. */
struct bpf_map_def rate __attribute__((section("maps"), used)) = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 64,
};

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;

/* struct ls_ctx_rst --- see substrate/ls_ctx_rst.h. 92 bytes after Phase 3 added
 * cause[]; file[] shrank from 48 to 32 to stay inside PREVAIL's 96-byte ceiling. */
struct ls_ctx_rst {
    __u32 cookie_lo, cookie_hi;      /* TMM's flow cookie; 0 = no flow */
    __u32 lineno, err, reason, file_len, cause_len;
    char  file[28];
    char  cause[36];
};
_Static_assert(sizeof(struct ls_ctx_rst) == 92, "host/program record mismatch");

#define THRESHOLD 5ull

__attribute__((section("fentry/rst_why"), used))
__u64
shield(struct ls_ctx_rst *c)
{
    /* Key on the call site: line plus a cheap fold of the first filename bytes.
     * Not a hash of the whole name --- a bounded, unrolled fold is enough to
     * separate sites and keeps the program trivially verifiable. */
    __u32 key = c->lineno ^ ((__u32)c->file[0] << 8) ^ ((__u32)c->file[1] << 16);
    __u64 *n = bpf_map_lookup_elem(&rate, &key);

    if (n) {
        __u64 v = *n + 1;
        bpf_map_update_elem(&rate, &key, &v, 0);
        /* THE THING THAT NEEDED STATE. A stateless program cannot express this
         * at all: it has no way to know this is the sixth. */
        return v > THRESHOLD ? 1ull : 0ull;
    }

    {
        __u64 one = 1;
        bpf_map_update_elem(&rate, &key, &one, 0);
    }
    return 0ull;
}
