/* alpn_reach.bpf.c --- the ALPN bounds check WIRED to the real ALPN bytes via a custom accessor.
 *
 * alpn_generic.bpf.c proved the bounded walk verifies once the bytes are in a stack buffer, but it
 * read from a raw register pointer --- it did not REACH the real ALPN data. The real bytes are found
 * via TMM's ssl_ext_get_by_type(sc, SSL_EXT_ALPN, ...), which a verified program cannot call. So a
 * HOST-SIDE accessor helper does the navigation and bound-copies the entry-list into the program's
 * stack buffer, returning its length. This is the bpftime pattern (custom helpers wrapping target-
 * specific accessors), adapted to what the STOCK pinned PREVAIL admits.
 *
 * WHY id 112 AND NOT A CUSTOM id. Tested on the pinned verifier (build box, PREVAIL 06769f7b): a
 * genuinely custom helper id (30, 100) is REFUSED --- the stock CLI only knows standard prototypes.
 * id 112 (bpf_probe_read_user) has exactly the prototype this needs --- (dst writable, len, src) ---
 * and PREVAIL admits it. We register OUR accessor at 112 in the VM (we use id 4 for real
 * probe_read, so 112 is free). PREVAIL verifies against the standard prototype; uBPF dispatches 112
 * to ls_h_alpn_get. Documented as a deliberate repurpose, not a coincidence.
 *
 * VERIFIED on the pinned toolchain: PASS at full 32-entry depth (same two verifier moves as
 * alpn_generic.bpf.c: widened overflow check + clamped accumulator).
 */
typedef unsigned int        __u32;
typedef unsigned long long  __u64;

/* id 112: OUR ssl-ALPN accessor. Prototype (dst, len, sc) matches bpf_probe_read_user, which is why
 * the stock verifier admits it. Returns the entry-list length copied into dst, or <=0 on failure. */
static long (*ls_h_alpn_get)(void *dst, __u32 len, __u64 sc) = (void *)112;

struct ls_ctx_generic { __u64 arg[5]; };

#define LS_SAFE_RETURN  1ull
#define LS_FALLTHROUGH  0ull
#define ALPN_MAX     64u
#define ALPN_ENTRIES 32u

__attribute__((section("fentry/ssl_alpn_match"), used))
__u64
shield(struct ls_ctx_generic *c)
{
    unsigned char buf[ALPN_MAX];
    unsigned int ix = 0, i, len, sz;
    long n;

    for (i = 0; i < ALPN_MAX; i++)
        buf[i] = 0;

    /* arg[0] is `struct ssl_ctx *sc` --- the accessor navigates it to the ALPN entry list. */
    n = ls_h_alpn_get(buf, ALPN_MAX, c->arg[0]);
    if (n <= 0)
        return LS_SAFE_RETURN;                        /* no ALPN, or the accessor refused */

    /* CLAMP BY ASSIGNMENT, not by branch. Bisected on the pinned verifier: when sz derives from a
     * helper RETURN (not a ctx read), `if (sz > MAX) return` loses the bound at the buffer access,
     * but `if (sz > MAX) sz = MAX` keeps a concrete upper bound PREVAIL trusts. The helper already
     * caps at ALPN_MAX; this makes the cap provable to the verifier. */
    sz = (unsigned int)n;
    if (sz > ALPN_MAX)
        sz = ALPN_MAX;
    if (sz == 0)
        return LS_SAFE_RETURN;

#pragma clang loop unroll(full)
    for (i = 0; i < ALPN_ENTRIES; i++) {
        if (ix >= sz)
            return LS_FALLTHROUGH;                    /* walked the list cleanly */

        len = buf[ix & (ALPN_MAX - 1)];

        if (len == 0)
            return LS_SAFE_RETURN;                    /* RFC 7301: zero-length entry */
        if ((unsigned long)ix + 1u + len > sz)        /* widened: entry runs past the extension */
            return LS_SAFE_RETURN;

        ix += 1u + len;
        if (ix >= ALPN_MAX)                           /* clamp: keep ix bounded for the verifier */
            ix = ALPN_MAX;
    }
    return LS_SAFE_RETURN;
}
