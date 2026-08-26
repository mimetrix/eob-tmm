/* http_observe --- a portable CO-RE *surface* (not a shield): per-request HTTP
 * observability/logic reading TMM's parser state directly. Fields are declared
 * minimally and marked preserve_access_index; their byte offsets are resolved by
 * NAME against the running build's BTF at load (ls_core_relo.c). The local offsets
 * below are placeholders --- deliberately NOT TMM's real offsets --- to prove the
 * relocation does the work. No bespoke helper, no baked offset, no rebuild.
 *
 * This is the kind of per-flow decision iRules cannot express: it reads the HTTP
 * parser's internal state and protocol minor-version, mid-parse.
 */
typedef unsigned char      __u8;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

/* Minimal relocatable view of TMM's struct http_parse_ctx. Real TMM layout has
 * these fields at other offsets (state@10, flags@11, version_num@12); resolution
 * is by field name, so this local ordering is irrelevant to correctness. */
struct http_parse_ctx {
    __u8 state;
    __u8 flags;
    __u8 version_num;   /* HTTP minor version: 0 => HTTP/1.0 */
} __attribute__((preserve_access_index));

struct ls_ctx_generic { __u64 arg[5]; };

__attribute__((section("fentry/http_parse_client_headers"), used))
__u64 shield(struct ls_ctx_generic *c)
{
    struct http_parse_ctx *h = (struct http_parse_ctx *)c->arg[0];
    __u8 st = 0, ver = 0;

    if (bpf_probe_read(&st,  sizeof st,  &h->state)       != 0) return 0ull;
    if (bpf_probe_read(&ver, sizeof ver, &h->version_num) != 0) return 0ull;

    /* Act on HTTP/1.0 requests, or on a specific parser state. */
    return (ver == 0 || st == 7) ? 1ull : 0ull;
}
