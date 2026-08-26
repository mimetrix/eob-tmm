/* PROBE surface --- attach to an internal function no iRule can hook, read the
 * HTTP parser's internal state, return a countable scalar the host buckets.
 * iRules fire at HTTP_REQUEST (after the parse); they cannot see the parser's
 * internal state, nor attach to this function. Fields resolved by CO-RE at load. */
typedef unsigned char __u8; typedef unsigned int __u32; typedef unsigned long long __u64;
static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;
struct http_parse_ctx { __u8 state; __u8 version_num; } __attribute__((preserve_access_index));
struct ls_ctx_generic { __u64 arg[5]; };
__attribute__((section("fentry/http_parse_client_headers"), used))
__u64 probe_parser(struct ls_ctx_generic *c)
{
    struct http_parse_ctx *h = (struct http_parse_ctx *)c->arg[0];
    __u8 ver = 0;
    if (bpf_probe_read(&ver, sizeof ver, &h->version_num) != 0) return 0ull;
    return (__u64)ver;                 /* host buckets by HTTP minor version */
}
