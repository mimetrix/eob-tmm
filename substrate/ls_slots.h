/* ls_slots.h --- which slot carries which ctx shape, in one place.
 *
 * WHY THIS FILE EXISTS. The slot numbers were spread across two files and one of
 * them was wrong: LS_CTX_SLOT_PARSE was 0 while its own comment two lines above
 * read "Slot 7 so it cannot collide with the shield in slot 0", and slot 0 is the
 * shield slot. So the trampoline handed every program in slot 0 a
 * struct ls_ctx_parse built from a0/a2 instead of the generic five-register ctx.
 *
 * That is not a crash. The program gets bytes of the right length and the wrong
 * meaning, verifies fine, runs fine, and produces a verdict about the wrong
 * fields. It survived because the intent lived in a comment and the value lived
 * in a macro, and nothing compared them.
 *
 * The comparison is now a _Static_assert. Two slots holding the same number is a
 * build failure, not a comment someone has to notice.
 *
 * Slot 0 is the shield by convention everywhere: the loader defaults to it, the
 * demos use it, and LS_CTX_SLOT_SHIELD names it so that "0" stops being a bare
 * literal that reads as "unset".
 */
#ifndef LS_SLOTS_H
#define LS_SLOTS_H

#define LS_CTX_SLOT_SHIELD  0   /* generic 5-register ctx --- no derivation      */
#define LS_CTX_SLOT_TP      1   /* tracepoint                                    */
#define LS_CTX_SLOT_DEV_A   2   /* dev probe                                     */
#define LS_CTX_SLOT_DEV_B   3   /* dev probe                                     */
#define LS_CTX_SLOT_ALPN    4   /* ssl_alpn_match --- ls_ctx_alpn_build_v         */
#define LS_CTX_SLOT_RST      5  /* rst_why --- ls_ctx_rst_build                  */
#define LS_CTX_SLOT_PARSE   7   /* http_parse_client_headers --- ls_ctx_build_parse
                                 * 7, not 0: 0 is the shield. This was the bug.  */

/* Distinctness, checked by the compiler rather than by reading. Pairwise because
 * the set is small and an enum would not catch a duplicated explicit value. */
_Static_assert(LS_CTX_SLOT_SHIELD != LS_CTX_SLOT_PARSE,
               "parse ctx would hijack the shield slot --- this was the 2026-08-17 bug");
_Static_assert(LS_CTX_SLOT_SHIELD != LS_CTX_SLOT_ALPN, "slot collision: shield/alpn");
_Static_assert(LS_CTX_SLOT_SHIELD != LS_CTX_SLOT_RST,  "slot collision: shield/rst");
_Static_assert(LS_CTX_SLOT_SHIELD != LS_CTX_SLOT_TP,   "slot collision: shield/tp");
_Static_assert(LS_CTX_SLOT_ALPN   != LS_CTX_SLOT_RST,  "slot collision: alpn/rst");
_Static_assert(LS_CTX_SLOT_ALPN   != LS_CTX_SLOT_PARSE, "slot collision: alpn/parse");
_Static_assert(LS_CTX_SLOT_RST    != LS_CTX_SLOT_PARSE, "slot collision: rst/parse");
_Static_assert(LS_CTX_SLOT_TP     != LS_CTX_SLOT_ALPN, "slot collision: tp/alpn");
_Static_assert(LS_CTX_SLOT_TP     != LS_CTX_SLOT_RST,  "slot collision: tp/rst");
_Static_assert(LS_CTX_SLOT_TP     != LS_CTX_SLOT_PARSE, "slot collision: tp/parse");
_Static_assert(LS_CTX_SLOT_DEV_A  != LS_CTX_SLOT_DEV_B, "slot collision: dev probes");

#endif /* LS_SLOTS_H */
