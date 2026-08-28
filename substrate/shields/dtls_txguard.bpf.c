/* SHIELD --- dtls_tx DTLS fragment-length stack overflow.
 *
 * Target: err_t dtls_tx(struct ssl_ctx *sc, enum ssl_rt rt, BYTE *p, SIZE sz)
 *         src/modules/hudfilter/ssl/ssl.c
 * Bug:    in the fragmentation path, `frag[SSL_SZ_RDATA]` is an on-stack record
 *         buffer, and per-fragment `fraglen` is clamped to `mleft` but NOT to the
 *         buffer size. When the DTLS segment size `mss` exceeds the record buffer,
 *         a long message drives a copy past `frag[]` --- a stack smash.
 * Fix:    401743ff1d adds `fraglen = MIN(fraglen, SSL_SZ_RDATA - DTLS_MSGHDR_SZ)`.
 *         Our deployed build (df2e3a63, git e2104734a9, 2026-08-11) PREDATES it, so
 *         the bug is LIVE for us. No CVE was ever assigned --- an internal finding,
 *         which is exactly why this is a mechanism demonstration, not a CVE claim.
 *
 * Detect (at entry, the fix's own precondition):
 *   mss  = sc->cf->mss            (connflow MSS, UINT16 --- up to 65535)
 *   sz   = arg[3]                 (the message size)
 *   overflow possible iff  mss > SSL_SZ_RDATA  AND the message is long enough to
 *   produce a fragment that big.
 * Act: LS_SAFE_RETURN --- host skips the body and returns the declared safe value
 *   ERR_BUF (=2), the SAME value dtls_tx itself returns when fraglen <= 0. The
 *   caller already handles ERR_BUF. err_t is an int (rax-representable), so this
 *   fits the v1 safe-return policy (trivial returns only, item 7).
 *
 * Fidelity note: the shield reads sc->cf->mss directly; the function uses
 * flow_unloop(sc->cf)->mss when the flow is looped. In the common (unlooped) case
 * these are identical. And SAFE_RETURN skips the WHOLE tx, coarser than the fix's
 * per-fragment clamp --- fail-closed, not a repair. Both are honest limits, not
 * defects: a shield prevents the crash, it does not reimplement the function.
 */
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

/* CO-RE views of only the fields read; resolved by name at load, across builds. */
struct connflow { __u16 mss; }        __attribute__((preserve_access_index));
struct ssl_ctx  { struct connflow *cf; } __attribute__((preserve_access_index));

/* Entry (fentry) tracing context: arg[0..4] = rdi..r8. PREVAIL verifies it as the
 * stock 96-byte all-scalar tracing ctx, exactly as the other fentry surfaces. */
struct ls_ctx_generic { __u64 arg[5]; };

#define LS_SAFE_RETURN  1ull
#define LS_FALLTHROUGH  0ull

/* SSL_SZ_RDATA --- the size of the on-stack frag[] record buffer (~16 KB; family of
 * SSL_SZ_TXREC_MAX = 16384). Resolved exactly at build time in the TMM include env;
 * nominal here. Normal DTLS mss is ~1500, so any mss at/above this is the abnormal,
 * overflow-enabling condition --- the shield never fires on well-formed traffic. */
#define LS_SSL_SZ_RDATA   16384u
/* DTLS_MSGHDR_SZ = sizeof(ssl_m)+sizeof(dtls_mx); a small constant. The message
 * must carry more than one buffer's worth of data to overflow. */
#define LS_DTLS_MSGHDR    16u

__attribute__((section("fentry/dtls_tx"), used))
__u64 dtls_txguard(struct ls_ctx_generic *c)
{
    struct ssl_ctx  *sc = (struct ssl_ctx *)c->arg[0];
    __u64            sz = c->arg[3];        /* SIZE sz --- 4th argument */
    struct connflow *cf = 0;
    __u16            mss = 0;

    if (sc == 0)
        return LS_FALLTHROUGH;
    if (bpf_probe_read(&cf, sizeof cf, &sc->cf) != 0 || cf == 0)
        return LS_FALLTHROUGH;              /* cannot read state --> fail open */
    if (bpf_probe_read(&mss, sizeof mss, &cf->mss) != 0)
        return LS_FALLTHROUGH;

    /* The fix's precondition, read at entry. */
    if ((__u32)mss > LS_SSL_SZ_RDATA &&
        sz > (__u64)(LS_SSL_SZ_RDATA - LS_DTLS_MSGHDR))
        return LS_SAFE_RETURN;              /* skip dtls_tx; host returns ERR_BUF */

    return LS_FALLTHROUGH;
}
