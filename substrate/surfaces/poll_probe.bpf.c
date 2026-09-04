/* SURFACE --- the poll loop, used to show a shield RUNNING on a binary that
 * carries no type information at all (02-RESEARCH-PARAMETERS.md P9 phase 3c).
 *
 * WHY device_poll AND NOT AN HTTP HOOK. Proving "a program with baked offsets
 * loads, arms and runs on a BTF-less binary" should not also depend on a working
 * traffic path. It did, and the dependency cost an hour: the cluster's port-80
 * virtual server is fastL4 (no HTTP parsing, so http_parse_client_headers is
 * never called) and its HTTP/2 server has no h2-speaking backend up. The poll
 * loop runs whether or not anything is being served, so it isolates the question.
 *
 * WHY IT READS A FIELD RATHER THAN JUST COUNTING. A program with no field access
 * carries no CO-RE relocation, so it would prove nothing about baked offsets ---
 * it would load on a BTF-less binary trivially. max_usec is DELIBERATELY declared
 * first here: locally it sits at offset 0, in TMM it sits at 4
 * (`dev_poll_param { poll_type @0, max_usec @4 }`, size 8). So the relocation has
 * to patch 0 -> 4, and if the offset were not baked the program would be reading
 * poll_type instead.
 *
 * MONITOR ONLY. The verdict is always FALLTHROUGH: nothing about the poll loop's
 * execution changes. A shield that alters device_poll is not something to try in
 * order to test a section header.
 */
typedef unsigned int __u32; typedef unsigned long long __u64;
static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

/* max_usec FIRST on purpose --- see above. */
struct dev_poll_param { __u32 max_usec; } __attribute__((preserve_access_index));
struct ls_ctx_generic { __u64 arg[5]; };
#define LS_FALLTHROUGH 0ull

__attribute__((section("fentry/device_poll"), used))
__u64 poll_probe(struct ls_ctx_generic *c)
{
    struct dev_poll_param *p = (struct dev_poll_param *)c->arg[0];
    __u32 budget = 0;
    /* The read is the point; the value is not acted on. bpf_probe_read faults
     * safely, so a wrong pointer costs an error return and never a crash. */
    (void)bpf_probe_read(&budget, sizeof budget, &p->max_usec);
    return LS_FALLTHROUGH;
}
