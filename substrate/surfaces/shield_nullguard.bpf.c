/* SHIELD surface --- a verdict that changes execution. If the parser's internal
 * pointer is NULL (the crash condition), return SAFE_RETURN so the host skips the
 * vulnerable body; otherwise fall through. iRules cannot intercept an internal
 * function to substitute a safe return. */
typedef unsigned int __u32; typedef unsigned long long __u64;
static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;
struct http_parse_ctx { void *parser; } __attribute__((preserve_access_index));
struct ls_ctx_generic { __u64 arg[5]; };
#define LS_SAFE_RETURN  1ull
#define LS_FALLTHROUGH  0ull
__attribute__((section("fentry/http_parse_client_headers"), used))
__u64 shield(struct ls_ctx_generic *c)
{
    struct http_parse_ctx *h = (struct http_parse_ctx *)c->arg[0];
    void *p = 0;
    if (bpf_probe_read(&p, sizeof p, &h->parser) != 0) return LS_FALLTHROUGH;
    return p == 0 ? LS_SAFE_RETURN : LS_FALLTHROUGH;   /* verdict gates the body */
}
