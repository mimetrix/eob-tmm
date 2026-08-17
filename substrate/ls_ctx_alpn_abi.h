/* The ALPN ctx boundary --- dependency-free, like ls_tp.h.
 *
 * ls_ctx_alpn_build() needs ssl_ext_get_by_type(), struct ssl_ctx and
 * SSL_EXT_ALPN, all of which live in TMM's -nostdinc world. ls_tramp.c is
 * STDINC and cannot see any of them. So the builder is compiled in the ssl
 * module's world (ls_ctx_alpn.c) and reached from the trampoline through this
 * one declaration, using only types that are ABI-identical on both sides.
 *
 * Do NOT "simplify" by declaring the real prototype here. That is the mistake
 * ls_prep.c documents: a struct pointer whose definition differs across the
 * boundary is a genuine ABI hazard, not a style question.
 */
#ifndef LS_CTX_ALPN_ABI_H
#define LS_CTX_ALPN_ABI_H

/* Fill `out` (which must be LS_CTX_ALPN_SZ bytes) from an ssl_ctx.
 * Returns 1 if there is an ALPN list worth judging, 0 to skip the program
 * entirely --- no ALPN extension, or one too short to hold a list. */
int ls_ctx_alpn_build_v(void *out, void *sc);

#define LS_CTX_ALPN_SZ    72u   /* sizeof(struct ls_ctx_alpn); asserted below */
/* Slot numbers are NOT here. They moved to ls_slots.h --- one copy, distinctness
 * checked by the compiler --- because duplicating them is what let PARSE and
 * SHIELD both be 0 without anything noticing.
 *
 * Not #included from here either: this header is pulled into the ssl module as
 * <local/base/ls_ctx_alpn_abi.h>, a -nostdinc include world where a quoted
 * include depends on which directory the header was staged into. ls_ctx_alpn.c
 * never uses a slot number, so ls_tramp.c --- the only dispatcher --- includes
 * ls_slots.h directly and nothing crosses include worlds to get it. */

#endif
