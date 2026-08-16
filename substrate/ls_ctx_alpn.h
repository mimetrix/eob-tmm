/* Host-side ctx builder for the ssl_alpn_match shield.
 *
 * Included by modules/hudfilter/ssl/ssl.c AFTER its own headers, so it inherits
 * that file's include world and needs none of its own --- the same discipline as
 * ls_tp_http.h. `struct ssl_ctx`, `err_t`, `BYTE`, `SIZE` and SSL_EXT_ALPN are
 * all in scope there and nowhere else.
 *
 * WHAT IT LIFTS AND WHY IT HAS TO. The program is armed at ssl_alpn_match's
 * ENTRY, where the ALPN bytes are not an argument --- the function derives them
 * from `sc` in its first ten lines. So the builder repeats exactly that
 * derivation, one step earlier:
 *
 *     ssl_ext_get_by_type(sc, SSL_EXT_ALPN, &ext, &sz)
 *     ext += sizeof(struct ssl_extension) + 2;      (4 + 2)
 *     sz  -= sizeof(struct ssl_extension) + 2;
 *
 * It calls TMM's own accessor rather than parsing the extension list again, so
 * there is no second parser to get wrong and no new attack surface --- if
 * ssl_ext_get_by_type is safe for the function, it is safe here.
 *
 * THE COPY IS THE POINT. eBPF cannot chase a pointer and PREVAIL will not admit
 * a program that tries, so the bytes are copied into a flat, bounded struct. An
 * unbounded copy would simply move the overread into the builder, which is why
 * the length is checked against LS_ALPN_MAX BEFORE the memcpy rather than
 * clamped inside it.
 *
 * 64 BYTES, AND THAT CEILING IS THE VERIFIER'S. PREVAIL's fentry ctx is 96
 * bytes; a 264-byte version of this struct was rejected outright with "Upper
 * bound must be at most 96". Real ALPN is far smaller --- "h2" plus "http/1.1"
 * is 14 bytes with length prefixes --- and anything longer sets `truncated`, on
 * which the program refuses rather than guesses.
 *
 * COST. This runs on the TLS handshake path, once per ClientHello carrying an
 * ALPN extension. It is not on the per-packet data path, which is why an
 * extension lookup plus a bounded memcpy is an acceptable price here and would
 * not be inside the poll loop.
 */
#ifndef LS_CTX_ALPN_H
#define LS_CTX_ALPN_H

#define LS_ALPN_MAX  64u                 /* power of two; see the 96-byte cap */

struct ls_ctx_alpn {
    unsigned int  alpn_sz;               /* entry-list size, after the 6-byte skip */
    unsigned int  truncated;             /* 1 if the real list exceeded LS_ALPN_MAX */
    unsigned char alpn[LS_ALPN_MAX];
};

/*
 * Fill the ctx from `sc`. Returns 1 if there is an ALPN list worth judging, 0 if
 * the shield should be skipped entirely.
 *
 * Zero is returned for the cases ssl_alpn_match itself bails on --- no ALPN
 * extension, or one too short to contain a list. Running the program on those
 * would make it answer a question about bytes that do not exist, and its verdict
 * would be noise rather than a finding.
 */
static inline int
ls_ctx_alpn_build(struct ls_ctx_alpn *c, struct ssl_ctx *sc)
{
    BYTE  *ext = 0;
    SIZE   sz  = 0;
    SIZE   i;

    c->alpn_sz   = 0;
    c->truncated = 0;
    for (i = 0; i < LS_ALPN_MAX; i++)
        c->alpn[i] = 0;

    if (ssl_ext_get_by_type(sc, SSL_EXT_ALPN, &ext, &sz) != ERR_OK)
        return 0;                              /* no ALPN --- nothing to judge */
    if (sz < (sizeof(struct ssl_extension) + 2))
        return 0;                              /* too short to hold a list     */
    if (ext == 0)
        return 0;

    /* The same skip the function performs: 4-byte extension header + the
     * 2-byte protocol-list length. */
    ext += sizeof(struct ssl_extension) + 2;
    sz  -= sizeof(struct ssl_extension) + 2;

    c->alpn_sz = (unsigned int)sz;
    if (sz > LS_ALPN_MAX) {
        c->truncated = 1;                      /* program refuses on this */
        return 1;
    }
    for (i = 0; i < sz; i++)
        c->alpn[i] = ext[i];
    return 1;
}

#endif /* LS_CTX_ALPN_H */
