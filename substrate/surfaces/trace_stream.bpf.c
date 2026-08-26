/* TRACE surface --- stream internal state off-box, live. Reads the HTTP parser's
 * internal fields and emits one record per invocation to the egress ring
 * (bpf_perf_event_output -> ls_drain). iRules cannot stream an internal function's
 * per-invocation state. Fields resolved by CO-RE; the ring map is resolved by the
 * loader's map glue at load. This surface observes only --- it never gates. */
typedef unsigned char __u8; typedef unsigned int __u32; typedef unsigned long long __u64;
static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;
static long (*bpf_perf_event_output)(void *, void *, __u64, void *, __u64) = (void *)25;

/* PERF_EVENT_ARRAY (type 4) == a handle on this thread's egress ring; max_entries
 * must be non-zero (ls_map_check_descriptor). */
struct bpf_map_def { __u32 type, key_size, value_size, max_entries, map_flags; };
struct bpf_map_def ls_ring __attribute__((section("maps"), used)) = {
    .type = 4, .key_size = 4, .value_size = 4, .max_entries = 1, .map_flags = 0,
};

struct http_parse_ctx { __u8 state; __u8 version_num; } __attribute__((preserve_access_index));
struct ls_ctx_generic { __u64 arg[5]; };
struct trace_rec { __u32 version; __u32 state; };

__attribute__((section("fentry/http_parse_client_headers"), used))
__u64 shield(struct ls_ctx_generic *c)
{
    struct http_parse_ctx *h = (struct http_parse_ctx *)c->arg[0];
    struct trace_rec rec = { 0, 0 };
    __u8 v = 0, s = 0;
    bpf_probe_read(&v, sizeof v, &h->version_num);
    bpf_probe_read(&s, sizeof s, &h->state);
    rec.version = v; rec.state = s;
    bpf_perf_event_output(c, &ls_ring, 0, &rec, sizeof rec);
    return 0ull;                       /* observe, never gate */
}
