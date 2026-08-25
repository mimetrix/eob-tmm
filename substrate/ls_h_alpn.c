/* ls_h_alpn.c --- the custom accessor helper that gives a verified program the real ALPN bytes.
 *
 * THE REACHABILITY PROBLEM IT SOLVES. A PREVAIL-verified program cannot call a TMM function, and the
 * ALPN entry list is found via TMM's ssl_ext_get_by_type(sc, SSL_EXT_ALPN, ...). So this HOST-side
 * helper does the navigation and bound-copies the entry list into the program's stack buffer. It is
 * the bpftime pattern (a custom helper wrapping a target-specific accessor), registered at uBPF
 * helper id 112. The program (substrate/shields/alpn_reach.bpf.c) then walks the buffer with a
 * bounds check PREVAIL admits.
 *
 * WHY id 112. Tested on the pinned verifier: a genuinely custom id is REFUSED by the stock PREVAIL,
 * which only knows standard prototypes. id 112 (bpf_probe_read_user) has exactly the prototype this
 * needs --- (dst writable, len, src) --- so PREVAIL admits the call; we use id 4 for the real
 * probe_read, leaving 112 free to carry this. Documented as a deliberate repurpose.
 *
 * FAULT SAFETY mirrors ls_h_probe_read: refuse null/oversize, and copy no more than the program's
 * buffer holds. The source (ext) comes from TMM's own accessor returning ERR_OK, so it is a valid
 * TMM-owned pointer; the destination is the VM's own stack. This runs in the trampoline, on a TMM
 * thread, where calling ssl_ext_get_by_type is legal --- which is the whole reason a helper exists
 * instead of doing this in the program.
 *
 * The navigation is byte-for-byte the typed builder's (ls_ctx_alpn.h ls_ctx_alpn_build): same
 * ssl_ext_get_by_type call, same "4-byte extension header + 2-byte protocol-list length" skip.
 */
#ifdef LS_ALPN_TEST
#  include "ls_h_alpn_stubs.h"          /* standalone unit test provides TMM types + a stub accessor */
#else
/* Same include world as the ssl-module ls_ctx_alpn.c --- ssl.h carries ssl_ext_get_by_type,
 * SSL_EXT_ALPN, struct ssl_ctx and struct ssl_extension. */
#  include <local/sys/def.h>
#  include <local/sys/err.h>
#  include <local/sys/queue.h>
#  include "ssl.h"
#  include "ssl_magic.h"
#  include <local/base/ls_ctx_alpn_abi.h>
#endif

#include <stdint.h>

#define LS_ALPN_GET_MAX  64u              /* must not exceed the shield's ALPN_MAX */

/* uBPF external_function_t: five uint64_t, no context. (dst, len, sc, -, -).
 * Returns the entry-list length copied into dst (1..len), or (uint64_t)-1 on any failure. */
uint64_t
ls_h_alpn_get(uint64_t dst, uint64_t len, uint64_t sc_u, uint64_t d, uint64_t e)
{
    BYTE  *ext = 0;
    SIZE   sz  = 0;
    SIZE   i, n, skip;
    (void)d; (void)e;

    if (dst == 0 || len == 0 || len > LS_ALPN_GET_MAX || sc_u == 0)
        return (uint64_t)-1;

    if (ssl_ext_get_by_type((struct ssl_ctx *)(uintptr_t)sc_u,
                            SSL_EXT_ALPN, &ext, &sz) != ERR_OK)
        return (uint64_t)-1;                       /* no ALPN --- nothing to judge */

    skip = sizeof(struct ssl_extension) + 2;       /* 4-byte ext header + 2-byte list length */
    if (ext == 0 || sz < skip)
        return (uint64_t)-1;                       /* too short to hold a list */

    ext += skip;
    sz  -= skip;                                   /* ext = entry-list start, sz = its length */

    n = (sz < (SIZE)len) ? sz : (SIZE)len;         /* never write past the program's buffer */
    for (i = 0; i < n; i++)
        ((BYTE *)(uintptr_t)dst)[i] = ext[i];

    return (uint64_t)n;
}
