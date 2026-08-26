/* NEGATIVE TEST (generic-ctx). PREVAIL MUST REFUSE this: it treats arg[0] as a raw
 * pointer and dereferences it directly, which is exactly what the memory-safety gate
 * exists to catch --- a verified program may not chase a pointer (it must use
 * bpf_probe_read, which range-checks). If this ever PASSES, the verifier is no longer
 * doing its job. bnk-build-programs.sh expects reject_* to be refused. */
typedef unsigned long long __u64;
struct ls_ctx_generic { __u64 arg[5]; };
__attribute__((section("fentry/reject_memory"), used))
__u64 shield(struct ls_ctx_generic *c)
{
    __u64 *p = (__u64 *)c->arg[0];   /* a raw, unproven pointer */
    return *p;                        /* direct dereference --- must be refused */
}
