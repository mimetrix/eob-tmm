/* EXIT surface --- attach to a function's RETURN, read its return value together
 * with the post-execution state the entry hook cannot see (at fentry the parser
 * has not populated its fields yet; at fexit it has). The exit context carries
 * the entry arguments AND the return value; PREVAIL verifies it as the stock
 * tracing context (a u64-array, fexit/ maps to BPF_PROG_TYPE_TRACING). Fields
 * resolved by CO-RE at load, exactly as the fentry surfaces. */
typedef unsigned char __u8; typedef unsigned int __u32; typedef unsigned long long __u64;
static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;
struct http_parse_ctx { __u8 state; __u8 version_num; } __attribute__((preserve_access_index));

/* The exit context: entry args arg[0..4] (rdi..r8) + the return value. Same shape
 * ls_fexit_leave builds. Reading c->ret is a scalar load at offset 40, well within
 * the 96-byte tracing ctx. */
struct ls_ctx_exit { __u64 arg[5]; __u64 ret; };

__attribute__((section("fexit/http_parse_client_headers"), used))
__u64 exit_probe(struct ls_ctx_exit *c)
{
    struct http_parse_ctx *h = (struct http_parse_ctx *)c->arg[0];
    __u8 ver = 0;
    if (bpf_probe_read(&ver, sizeof ver, &h->version_num) != 0)
        return c->ret;                 /* fall back to the raw result on read fault */
    return (__u64)ver + (c->ret & 0xffull);  /* fold post-parse state WITH the return value */
}
