/* alpn_generic.bpf.c --- the ALPN entry-list bounds check on the GENERIC path.
 *
 * WHY THIS EXISTS, AND WHAT IT RECOVERS. alpn_guard.bpf.c (the TYPED path) is recorded FALSIFIED:
 * PREVAIL refused it with "154: Upper bound must be at most 96" --- the 96-byte fentry ctx ceiling,
 * because the typed builder copies the ALPN bytes INTO the ctx. This version keeps the bytes OUT of
 * the ctx: the program reads them with bpf_probe_read into its own stack buffer (generic_probe.bpf.c's
 * pattern), so the ctx stays the small register context and the ceiling cannot bind. VERIFIED on the
 * pinned toolchain (build box, clang-18, PREVAIL v0.2.5 06769f7b, gates
 * --termination --no-division-by-zero --strict): PASS at the full 32-entry depth. The verification
 * that killed the typed shield does not kill this one.
 *
 * TWO PREVAIL-FRIENDLY MOVES THAT ARE LOAD-BEARING --- both were found by bisection on the pinned
 * verifier, not by reasoning, and removing either reintroduces the failure:
 *   1. WIDEN THE OVERFLOW CHECK to 64-bit: `(unsigned long)ix + 1u + len > sz`. In 32-bit the sum can
 *      wrap, and PREVAIL loses the bound on `ix` across the unrolled walk; widening keeps it precise.
 *   2. CLAMP THE ACCUMULATOR: `if (ix >= ALPN_MAX) ix = ALPN_MAX;`. This keeps `ix` in [0, 64] every
 *      iteration so its interval never widens past the buffer; correctness is unaffected because any
 *      ix >= sz (sz <= 64) exits at the top of the next iteration anyway.
 * The masked access `b[ix & (ALPN_MAX-1)]` is belt-and-braces: when the access is reached ix < sz <=
 * ALPN_MAX already, so the mask is a semantic no-op that also proves the bound to the verifier.
 *
 * WHAT THIS SETTLES AND WHAT IT DOES NOT. It settles the VERIFICATION question --- the generic path
 * dissolves the ctx ceiling and PREVAIL admits the bounded walk. It does NOT settle REACHABILITY: the
 * real ALPN bytes are found via TMM's ssl_ext_get_by_type(sc,...), which a generic program cannot
 * call. Here the program reads from a pointer/len handed in registers (arg[1]/arg[2]); wiring it to
 * the true ALPN pointer in production needs a fixed pointer chain from sc or a custom accessor helper
 * (the bpftime pattern). That is the next open problem, tracked separately.
 */
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

struct ls_ctx_generic { __u64 arg[5]; };

#define LS_SAFE_RETURN  1ull
#define LS_FALLTHROUGH  0ull
#define ALPN_MAX     64u          /* bytes we inspect; power of two */
#define ALPN_ENTRIES 32u          /* max entries walked (fully unrolled) */

__attribute__((section("uprobe/ssl_alpn_match"), used))
__u64
shield(struct ls_ctx_generic *c)
{
    unsigned char buf[ALPN_MAX];
    unsigned int sz = (unsigned int)c->arg[2];      /* entry-list size */
    unsigned int ix = 0, i, len;

    if (sz == 0 || sz > ALPN_MAX)
        return LS_SAFE_RETURN;                        /* nothing to see, or too big: refuse */

    for (i = 0; i < ALPN_MAX; i++)
        buf[i] = 0;

    if (bpf_probe_read(buf, ALPN_MAX, (const void *)c->arg[1]) != 0)
        return LS_SAFE_RETURN;                        /* bad pointer: refuse, never fault */

#pragma clang loop unroll(full)
    for (i = 0; i < ALPN_ENTRIES; i++) {
        if (ix >= sz)
            return LS_FALLTHROUGH;                    /* walked the list cleanly */

        len = buf[ix & (ALPN_MAX - 1)];               /* entry length; masked for the verifier */

        if (len == 0)
            return LS_SAFE_RETURN;                    /* RFC 7301: zero-length entry */
        if ((unsigned long)ix + 1u + len > sz)        /* WIDENED: entry runs past the extension */
            return LS_SAFE_RETURN;

        ix += 1u + len;
        if (ix >= ALPN_MAX)                           /* CLAMP: keep ix bounded for the verifier */
            ix = ALPN_MAX;
    }
    return LS_SAFE_RETURN;                             /* more entries than real: hostile */
}
