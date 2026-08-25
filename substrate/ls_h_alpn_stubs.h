/* ls_h_alpn_stubs.h --- TMM type + accessor stubs so ls_h_alpn.c's LOGIC can be unit-tested off
 * the TMM tree. NOT used in the real build (that includes the real <local/...> headers). The stub
 * ssl_ext_get_by_type is driven by check_alpn_get.c to exercise every path. */
#ifndef LS_H_ALPN_STUBS_H
#define LS_H_ALPN_STUBS_H
#include <stdint.h>
typedef unsigned char  BYTE;
typedef unsigned long  SIZE;
typedef int            err_t;
#define ERR_OK 0
#define SSL_EXT_ALPN 16
struct ssl_ctx { int _; };
struct ssl_extension { unsigned char hdr[4]; };   /* sizeof == 4, matches the real header size */
/* the test sets these to control the stub's answer */
extern int       g_stub_rc;      /* what ssl_ext_get_by_type returns */
extern BYTE     *g_stub_ext;     /* the extension pointer it yields */
extern SIZE      g_stub_len;     /* the extension length it yields */
static inline err_t
ssl_ext_get_by_type(struct ssl_ctx *sc, unsigned short type, BYTE **out, SIZE *outlen)
{
    (void)sc; (void)type;
    *out = g_stub_ext; *outlen = g_stub_len;
    return g_stub_rc;
}
#endif
