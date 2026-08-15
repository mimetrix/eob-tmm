/* Restores the bounds check removed from ssl_alpn_match().
 *
 * THE DEFECT (commit c806f1b2e8, reverted in tmm:vuln-alpn). The ALPN list is
 * walked using each entry's own length byte as the stride:
 *
 *     for (ix = 0; ix < alpn_ext_sz; ix += 1 + alpn_ext[ix])
 *
 * with no check that entry ix stays inside the extension. The length byte comes
 * from the client's TLS ClientHello, so a crafted value drives ix past
 * alpn_ext_sz and the memcmp below reads out of bounds. A zero length is also
 * invalid per RFC 7301.
 *
 * WHY THE TRIP COUNT IS CONSTANT AND THE INDEX IS MASKED. PREVAIL will not admit
 * a loop bounded by an attacker-supplied length --- which is precisely the
 * property the original code got wrong, so the verifier is refusing the exact
 * mistake being fixed. Both bounds here are compile-time: at most
 * LS_ALPN_ENTRIES iterations, and every index is masked into [0, LS_ALPN_MAX).
 * The mask is not defensive decoration; it is what makes each access provably
 * in range without reasoning about alpn_sz at all.
 *
 * DISPOSITION. SAFE_RETURN on a malformed list --- the host applies the hook's
 * safe value and ssl_alpn_match never runs, which is what the upstream fix does
 * by breaking out of the loop. FALLTHROUGH otherwise, so well-formed ALPN is
 * untouched.
 */
#include "ls_ctx_alpn_bpf.h"

__attribute__((section("fentry/ssl_alpn_match"), used))
unsigned long long
shield(struct ls_ctx_alpn *c)
{
    unsigned int sz = c->alpn_sz;
    unsigned int ix = 0;
    unsigned int i, len;

    /* Larger than we can see, or nothing to see: refuse rather than guess. */
    if (c->truncated != 0)
        return LS_SAFE_RETURN;
    if (sz == 0 || sz > LS_ALPN_MAX)
        return LS_SAFE_RETURN;

    /* FULLY UNROLLED, and the reason matters. Written as a normal counted loop,
     * -O2 makes the attacker-driven `ix` the induction variable and PREVAIL then
     * cannot bound the backedge --- "Loop counter is too large". Unrolling
     * removes the backedge entirely, so termination is structural rather than
     * something the verifier has to prove about hostile input. Same lesson as
     * folded_loop.bpf.c: verify the OBJECT, not the source. */
#pragma clang loop unroll(full)
    for (i = 0; i < LS_ALPN_ENTRIES; i++) {
        if (ix >= sz)
            return LS_FALLTHROUGH;          /* walked the list cleanly */

        len = c->alpn[ix & (LS_ALPN_MAX - 1)];

        if (len == 0)
            return LS_SAFE_RETURN;          /* RFC 7301: zero-length entry */
        if (ix + 1u + len > sz)
            return LS_SAFE_RETURN;          /* entry runs past the extension */

        ix += 1u + len;
    }

    /* More entries than a real ClientHello carries: treat as hostile. */
    return LS_SAFE_RETURN;
}
