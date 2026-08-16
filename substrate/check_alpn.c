/* Does the ALPN builder + shield actually catch the crafted ClientHello?
 *
 * Two halves that must agree and are written in different languages, compiled by
 * different compilers, for different targets:
 *
 *   ls_ctx_alpn.h        host C, inside ssl.c's include world, lifts the bytes
 *   alpn_guard.bpf.c     eBPF, verified by PREVAIL, judges them
 *
 * Neither can be exercised on the cluster until a TLS listener exists, so this
 * runs both against the exact payloads loader-client/alpn_trigger.py emits. If
 * the pair disagrees here, no amount of cluster time will help; if they agree,
 * the only thing left to prove live is reachability.
 *
 * THE CONTROL MATTERS AS MUCH AS THE CATCH. A shield that flags everything
 * "works" on the malformed case and is useless. Well-formed ALPN --- which is
 * every real ClientHello --- must fall through untouched, or arming this in
 * enforce would break TLS for everyone.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ---- mocks for ssl.c's world, mirroring modules/hudfilter/ssl/ ---------- */
typedef unsigned char  BYTE;
typedef unsigned long  SIZE;
typedef unsigned short UINT16;
typedef int            err_t;
#define ERR_OK 0
#define SSL_EXT_ALPN 16

struct ssl_extension { UINT16 type; UINT16 sz; BYTE data[0]; } __attribute__((packed));

/* A stand-in for the real accessor: hands back whatever the test staged. */
struct ssl_ctx { BYTE *ext; SIZE sz; int present; };

static err_t
ssl_ext_get_by_type(struct ssl_ctx *sc, UINT16 type, BYTE **out, SIZE *osz)
{
    (void)type;
    if (!sc->present)
        return 1;
    *out = sc->ext; *osz = sc->sz;
    return ERR_OK;
}

#include "ls_ctx_alpn.h"

/* ---- the shield's logic, as alpn_guard.bpf.c expresses it -------------- */
#define LS_ALPN_ENTRIES 64u
#define FALLTHROUGH 0u
#define SAFE_RETURN 1u

static unsigned int
shield(const struct ls_ctx_alpn *c)
{
    unsigned int sz = c->alpn_sz, ix = 0, i, len;
    if (c->truncated != 0)          return SAFE_RETURN;
    if (sz == 0 || sz > LS_ALPN_MAX) return SAFE_RETURN;
    for (i = 0; i < LS_ALPN_ENTRIES; i++) {
        if (ix >= sz) return FALLTHROUGH;
        len = c->alpn[ix & (LS_ALPN_MAX - 1)];
        if (len == 0)             return SAFE_RETURN;
        if (ix + 1u + len > sz)   return SAFE_RETURN;
        ix += 1u + len;
    }
    return SAFE_RETURN;
}

/* Build the extension exactly as alpn_trigger.py does: 4-byte header, 2-byte
 * truthful list length, then entries. */
static void
stage(struct ssl_ctx *sc, BYTE *buf, const BYTE *entries, SIZE n)
{
    buf[0] = 0; buf[1] = SSL_EXT_ALPN;          /* type, big-endian */
    buf[2] = (BYTE)((n + 2) >> 8); buf[3] = (BYTE)(n + 2);
    buf[4] = (BYTE)(n >> 8);       buf[5] = (BYTE)n;
    memcpy(buf + 6, entries, n);
    sc->ext = buf; sc->sz = 6 + n; sc->present = 1;
}

int
main(void)
{
    struct ls_ctx_alpn c;
    struct ssl_ctx sc;
    BYTE buf[512];
    int n = 0;

    /* 1. no ALPN extension --- skip the shield entirely rather than judge
     *    bytes that do not exist */
    sc.present = 0;
    assert(ls_ctx_alpn_build(&c, &sc) == 0);                                n++;

    /* 2. present but too short to hold a list */
    sc.present = 1; sc.ext = buf; sc.sz = 4;
    assert(ls_ctx_alpn_build(&c, &sc) == 0);                                n++;

    /* 3. THE CONTROL: real ALPN, "h2" + "http/1.1". Must FALL THROUGH ---
     *    every genuine ClientHello looks like this, and flagging it would
     *    break TLS for everyone. */
    {
        const BYTE e[] = { 2,'h','2', 8,'h','t','t','p','/','1','.','1' };
        stage(&sc, buf, e, sizeof e);
        assert(ls_ctx_alpn_build(&c, &sc) == 1);                            n++;
        assert(c.alpn_sz == sizeof e && c.truncated == 0);                  n++;
        assert(memcmp(c.alpn, e, sizeof e) == 0);   /* copied verbatim */   n++;
        assert(shield(&c) == FALLTHROUGH);                                  n++;
    }

    /* 4. THE CATCH: alpn_trigger.py --mode oob --- "h2" then a final entry
     *    claiming 255 bytes with none following. */
    {
        const BYTE e[] = { 2,'h','2', 0xff };
        stage(&sc, buf, e, sizeof e);
        assert(ls_ctx_alpn_build(&c, &sc) == 1);                            n++;
        assert(c.alpn_sz == 4);                                             n++;
        assert(shield(&c) == SAFE_RETURN);                                  n++;
    }

    /* 5. --mode zero --- zero-length entry, invalid per RFC 7301 */
    {
        const BYTE e[] = { 2,'h','2', 0x00 };
        stage(&sc, buf, e, sizeof e);
        assert(ls_ctx_alpn_build(&c, &sc) == 1);                            n++;
        assert(shield(&c) == SAFE_RETURN);                                  n++;
    }

    /* 6. an entry that overruns by exactly one byte --- the boundary, where an
     *    off-by-one in either half would hide */
    {
        const BYTE e[] = { 2,'h','2', 2,'x' };      /* claims 2, one byte left */
        stage(&sc, buf, e, sizeof e);
        assert(ls_ctx_alpn_build(&c, &sc) == 1);                            n++;
        assert(shield(&c) == SAFE_RETURN);                                  n++;
    }

    /* 7. and exactly-fits must NOT be flagged --- the other side of that edge */
    {
        const BYTE e[] = { 2,'h','2', 1,'x' };
        stage(&sc, buf, e, sizeof e);
        assert(ls_ctx_alpn_build(&c, &sc) == 1);                            n++;
        assert(shield(&c) == FALLTHROUGH);                                  n++;
    }

    /* 8. oversized list: truncated, and refused rather than guessed at */
    {
        BYTE e[LS_ALPN_MAX + 8];
        memset(e, 1, sizeof e);
        stage(&sc, buf, e, sizeof e);
        assert(ls_ctx_alpn_build(&c, &sc) == 1);                            n++;
        assert(c.truncated == 1);                                           n++;
        assert(shield(&c) == SAFE_RETURN);                                  n++;
    }

    printf("ok    ls_ctx_alpn.h + alpn_guard  (%d assertions: real ALPN falls "
           "through, crafted entry caught, boundary both sides)\n", n);
    return 0;
}
