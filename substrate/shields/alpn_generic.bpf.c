/* alpn_generic.bpf.c --- the ALPN bounds check on the GENERIC path.
 *
 * WHY THIS EXISTS. alpn_guard.bpf.c (the TYPED path) is recorded FALSIFIED: PREVAIL refused it
 * with "154: Upper bound must be at most 96" --- the 96-byte fentry ctx ceiling, because the typed
 * builder copies the ALPN bytes INTO the ctx. This version keeps the bytes OUT of the ctx: the
 * program reads them with bpf_probe_read into its own stack buffer (exactly generic_probe.bpf.c's
 * pattern, which verifies), so the ctx stays the small five-register generic context and the
 * ceiling cannot bind.
 *
 * WHAT THIS TESTS AND WHAT IT DOES NOT. It tests the VERIFICATION question --- does PREVAIL admit
 * probe_read-into-stack + the bounded ALPN walk. It does NOT settle REACHABILITY: the real ALPN
 * bytes are found via TMM's ssl_ext_get_by_type(sc,...), which a generic program cannot call. For
 * this verification test the program reads from a pointer handed in a register; wiring it to the
 * true ALPN pointer in production needs either a fixed pointer chain or a custom accessor helper.
 */
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

struct ls_ctx_generic { __u64 arg[5]; };

#define LS_SAFE_RETURN  1ull
#define LS_FALLTHROUGH  0ull
#define ALPN_MAX     64u          /* bytes we will inspect; power of two */
#define ALPN_ENTRIES 32u          /* max list entries walked (fully unrolled) */

__attribute__((section("fentry/ssl_alpn_match"), used))
__u64
shield(struct ls_ctx_generic *c)
{
    unsigned char buf[ALPN_MAX];
    unsigned int sz = (unsigned int)c->arg[2];      /* skip_ext_len, as a stand-in size */
    unsigned int ix = 0, i, len;

    if (sz == 0 || sz > ALPN_MAX)
        return LS_SAFE_RETURN;                        /* nothing to see, or too big: refuse */

    for (i = 0; i < ALPN_MAX; i++)
        buf[i] = 0;

    /* Read the bytes OUT of the ctx --- this is the whole difference from the typed path. */
    if (bpf_probe_read(buf, ALPN_MAX, (const void *)c->arg[1]) != 0)
        return LS_SAFE_RETURN;                        /* bad pointer: refuse, never fault */

    /* The same bounded walk alpn_guard does, fully unrolled --- no back-edge for PREVAIL. */
#pragma clang loop unroll(full)
    for (i = 0; i < ALPN_ENTRIES; i++) {
        if (ix >= sz)
            return LS_FALLTHROUGH;                    /* walked the list cleanly */

        len = buf[ix & (ALPN_MAX - 1)];

        if (len == 0)
            return LS_SAFE_RETURN;                    /* RFC 7301: zero-length entry */
        if (ix + 1u + len > sz)
            return LS_SAFE_RETURN;                    /* entry runs past the extension */

        ix += 1u + len;
    }
    return LS_SAFE_RETURN;                             /* more entries than real: hostile */
}
