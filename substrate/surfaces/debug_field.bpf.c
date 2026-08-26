/* DEBUG surface --- ad-hoc introspection. Read ONE named field of a live object
 * and return its value; re-point by loading a sibling program naming a different
 * field. This one reads a field of struct ssl_ctx (a different struct than the
 * probe), proving "any struct, any field, by name" --- gdb can't do this live and
 * iRules have no variable for it. */
typedef unsigned int __u32; typedef unsigned long long __u64;
static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;
/* minimal relocatable view of ssl_ctx: we only name the field we want */
struct ssl_ctx { void *cf; } __attribute__((preserve_access_index));
struct ls_ctx_generic { __u64 arg[5]; };
__attribute__((section("fentry/ssl_alpn_match"), used))
__u64 debug_field(struct ls_ctx_generic *c)
{
    struct ssl_ctx *sc = (struct ssl_ctx *)c->arg[0];
    __u64 v = 0;
    if (bpf_probe_read(&v, sizeof v, &sc->cf) != 0) return 0ull;
    return v;                          /* the live field value, reported to the host */
}
