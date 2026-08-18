/* tmm:net:reset:gated --- emit only when a reset site exceeds a RATE, not a total.
 *
 * THIS IS WHAT THE CLOCK AND THE EMIT HELPER BOUGHT, and it is worth stating what was
 * impossible before either existed:
 *
 *   - Without bpf_ktime_get_ns a program cannot know what time it is, so every threshold
 *     is a lifetime total. rate_watch's "over 5" means "this site fired more than five
 *     times EVER since the program was loaded" --- true on a healthy box after an hour,
 *     and therefore useless. There was no way to express "five times in the last second".
 *
 *   - Without bpf_ringbuf_output the HOST publishes a record for every event, after the
 *     program runs. A program could compute anything it liked and still not decide
 *     whether the record was worth emitting. The record rate was fixed at the event rate.
 *
 * Together they mean a program can watch a high-frequency site and stay quiet until it
 * matters. That is the whole reason the timer hook was on the plan, and it needs no timer.
 *
 * WHAT IT DOES. Keys on the reset site. Holds a window start and a count per site. Inside
 * the window it counts. When the window expires it starts a new one. When the count
 * crosses the threshold INSIDE a window it emits one record and marks the window so it
 * does not emit again until the next one --- so a site failing at 10,000/sec produces one
 * record per second, not ten thousand.
 *
 * ALWAYS FALLS THROUGH --- observation only. No `return LS_SAFE_RETURN` anywhere.
 *
 * THE HOST STILL PUBLISHES ITS OWN RECORD per event, because ls_tp_dispatch does that
 * unconditionally. So arming this in the demo shows BOTH streams: the raw per-event feed
 * and this program's gated one, distinguishable by "hook" ("reset" versus "prog"). Making
 * the host's publish conditional on the program is the obvious next step and is NOT done
 * --- said plainly rather than implied by this program's existence.
 */
typedef unsigned int  __u32;
typedef unsigned long long __u64;

struct bpf_map_def {
    __u32 type, key_size, value_size, max_entries, map_flags;
};
#define BPF_MAP_TYPE_HASH    1
#define BPF_MAP_TYPE_RINGBUF 27

/* The window state, one per reset site. 24 bytes, inside LS_MAP_VAL_MAX (32). */
struct window {
    __u64 start_ns;      /* when this window opened                        */
    __u64 count;         /* events seen in it                              */
    __u64 emitted;       /* 1 once this window has produced a record       */
};

struct bpf_map_def rate_window __attribute__((section("maps"), used)) = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct window),
    .max_entries = 64,
};

/* Resolves to the thread's EXISTING egress ring, not to new storage --- see
 * LS_MAP_TYPE_RINGBUF in ls_map.h. key_size and value_size are 0 by definition and
 * max_entries is a byte count, which is why the host admits this descriptor on its own
 * terms rather than through the hash checks. */
struct bpf_map_def egress __attribute__((section("maps"), used)) = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 4096,
};

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_ringbuf_output)(void *, void *, __u64, __u64) = (void *)130;

/* struct ls_ctx_rst --- substrate/ls_ctx_rst.h, 92 bytes. */
struct ls_ctx_rst {
    __u32 cookie_lo, cookie_hi;
    __u32 lineno, err, reason, file_len, cause_len;
    char  file[28];
    char  cause[36];
};
_Static_assert(sizeof(struct ls_ctx_rst) == 92, "host/program record mismatch");

/* What this program emits when a site is over rate. Its own shape, because the host does
 * not know it --- the drain reports program records as length and hex, and interpreting
 * them is this program's contract with its own consumer. */
struct alert {
    __u32 site;          /* the same key this program groups by         */
    __u32 lineno;
    __u64 count;         /* events in the window that tripped it        */
    __u64 window_ns;     /* how long that window had been open          */
};

#define WINDOW_NS  1000000000ull   /* one second */
#define THRESHOLD  5ull

#define LS_FALLTHROUGH 0ull

__attribute__((section("fentry/rst_why"), used))
__u64
shield(struct ls_ctx_rst *c)
{
    /* Same site key as rate_watch: line plus a cheap fold of the first filename bytes.
     * A bounded unrolled fold, not a hash of the whole name --- enough to separate sites
     * and trivially verifiable. */
    __u32 key = c->lineno ^ ((__u32)c->file[0] << 8) ^ ((__u32)c->file[1] << 16);
    __u64 now = bpf_ktime_get_ns();
    struct window *w = bpf_map_lookup_elem(&rate_window, &key);
    struct window nw;

    if (!w) {
        nw.start_ns = now;
        nw.count    = 1;
        nw.emitted  = 0;
        bpf_map_update_elem(&rate_window, &key, &nw, 0);
        return LS_FALLTHROUGH;
    }

    nw = *w;

    /* A NEW WINDOW. Note the comparison is on elapsed time, which is only sound because
     * the clock is MONOTONIC --- on a REALTIME step backwards `now - start_ns` would wrap
     * to an enormous unsigned value, every window would look expired, and the gate would
     * emit on every event. That is why the helper does not use REALTIME. */
    if (now - nw.start_ns >= WINDOW_NS) {
        nw.start_ns = now;
        nw.count    = 1;
        nw.emitted  = 0;
        bpf_map_update_elem(&rate_window, &key, &nw, 0);
        return LS_FALLTHROUGH;
    }

    nw.count = nw.count + 1;

    /* Over rate, and this window has not spoken yet. One record per window per site, so a
     * site failing at 10,000/sec yields one record a second rather than ten thousand. */
    if (nw.count >= THRESHOLD && nw.emitted == 0) {
        struct alert a;
        a.site      = key;
        a.lineno    = c->lineno;
        a.count     = nw.count;
        a.window_ns = now - nw.start_ns;
        bpf_ringbuf_output(&egress, &a, sizeof a, 0);
        nw.emitted = 1;
    }

    bpf_map_update_elem(&rate_window, &key, &nw, 0);
    return LS_FALLTHROUGH;
}
