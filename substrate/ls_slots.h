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
/* slot 2 reassigned from a dev probe to rst_why_preserve_va, so each of the four
 * reset functions has its own slot and the record can name which one fired. */
#define LS_CTX_SLOT_RST_PRE_VA 2
/* slot 3 reassigned from a dev probe to rst_why_preserve --- the dev probes were
 * never used for anything that outlived a session. */
#define LS_CTX_SLOT_ALPN    4   /* ssl_alpn_match --- ls_ctx_alpn_build_v         */
#define LS_CTX_SLOT_RST      5  /* rst_why --- ls_ctx_rst_build                  */
#define LS_CTX_SLOT_PARSE   7   /* http_parse_client_headers --- ls_ctx_build_parse
                                 * 7, not 0: 0 is the shield. This was the bug.  */
/*
 * THE OTHER TWO RESET FUNCTIONS. RST_WHY* macros expand to three different
 * functions, and hooking only rst_why covers 966 of 1,116 call sites:
 *
 *   rst_why         (uf, file, lineno, err, reason, cause)            966 sites
 *   rst_why_va      (uf, file, lineno, err, reason, cause, fmt, ...)  131 sites
 *   rst_why_preserve(uf, file, lineno, err, cause)                     19 sites
 *
 * rst_why_va's first SIX arguments are identical to rst_why's --- the varargs begin
 * at the seventh --- and the trampoline reads only the first six registers. So it
 * needs no builder of its own, just its own slot and address. The header states the
 * cause is a static string even there; the varargs carry ADDITIONAL detail we do not
 * read.
 *
 * rst_why_preserve has no `reason` argument, so the cause is arg4 (r8) rather than
 * arg5 (r9). That is the only shape difference, and it is why it gets its own slot
 * rather than sharing.
 *
 * VARARGS CAVEAT, stated because it is a data-plane risk and not a theoretical one:
 * trampoline_x86_64.S does not save xmm0-15. A varargs call site may have passed
 * floating-point arguments there with rax as the vector count. uBPF's generated code
 * does not touch SSE today, but that is a property of today's uBPF rather than a
 * guarantee. A clobber would corrupt the FORMATTED extra data downstream, not our
 * record.
 */
#define LS_CTX_SLOT_RST_VA  6   /* rst_why_va --- same 6 named args as rst_why   */
#define LS_CTX_SLOT_RST_PRE 3   /* rst_why_preserve --- 5 args, cause in arg4    */

/*
 * ssl__err --- why the TLS handshake or record layer failed. 475 call sites.
 *
 *   ssl__err(sc, alert, __func__, __LINE__, ...)
 *      a0 sc      struct ssl_ctx *   -> flow cookie via ls_ssl_cookie()
 *      a1 alert   enum ssl_alert
 *      a2 func    const char *       __func__, NOT __FILE__
 *      a3 line    int
 *      a4 msg     const char *       the FIRST VARARG
 *
 * Slot 8 needed the trampoline expanded from 8 slots to 12 --- see the LS_TRAMP
 * expansions in trampoline_x86_64.S. Sharing an existing slot was the alternative and
 * is exactly the 2026-08-17 failure this file was created to prevent: two hooks of
 * different ctx shapes on one slot means the wrong builder runs and produces a record
 * of the right length and the wrong meaning.
 *
 * VARARGS, like rst_why_va: the message is the first vararg, so it arrives in r8 and
 * the same xmm caveat applies --- the trampoline saves no xmm registers, and a varargs
 * site may have passed FP arguments there with rax as the vector count. A clobber
 * corrupts the formatted text downstream, not our record.
 */
#define LS_CTX_SLOT_SSLERR  8   /* ssl__err --- ls_ctx_sslerr_build              */

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
_Static_assert(LS_CTX_SLOT_RST     != LS_CTX_SLOT_RST_VA,  "slot collision: rst/rst_va");
_Static_assert(LS_CTX_SLOT_RST     != LS_CTX_SLOT_RST_PRE, "slot collision: rst/rst_pre");
_Static_assert(LS_CTX_SLOT_RST_VA  != LS_CTX_SLOT_RST_PRE, "slot collision: rst_va/rst_pre");
_Static_assert(LS_CTX_SLOT_SHIELD  != LS_CTX_SLOT_RST_VA,  "slot collision: shield/rst_va");
_Static_assert(LS_CTX_SLOT_SHIELD  != LS_CTX_SLOT_RST_PRE, "slot collision: shield/rst_pre");
_Static_assert(LS_CTX_SLOT_ALPN    != LS_CTX_SLOT_RST_VA,  "slot collision: alpn/rst_va");
_Static_assert(LS_CTX_SLOT_ALPN    != LS_CTX_SLOT_RST_PRE, "slot collision: alpn/rst_pre");
_Static_assert(LS_CTX_SLOT_PARSE   != LS_CTX_SLOT_RST_VA,  "slot collision: parse/rst_va");
_Static_assert(LS_CTX_SLOT_PARSE   != LS_CTX_SLOT_RST_PRE, "slot collision: parse/rst_pre");
_Static_assert(LS_CTX_SLOT_TP      != LS_CTX_SLOT_RST_VA,  "slot collision: tp/rst_va");
_Static_assert(LS_CTX_SLOT_TP      != LS_CTX_SLOT_RST_PRE, "slot collision: tp/rst_pre");
_Static_assert(LS_CTX_SLOT_RST_PRE_VA != LS_CTX_SLOT_RST,     "slot collision: rst_pre_va/rst");
_Static_assert(LS_CTX_SLOT_RST_PRE_VA != LS_CTX_SLOT_RST_VA,  "slot collision: rst_pre_va/rst_va");
_Static_assert(LS_CTX_SLOT_RST_PRE_VA != LS_CTX_SLOT_RST_PRE, "slot collision: rst_pre_va/rst_pre");
_Static_assert(LS_CTX_SLOT_RST_PRE_VA != LS_CTX_SLOT_SHIELD,  "slot collision: rst_pre_va/shield");
_Static_assert(LS_CTX_SLOT_RST_PRE_VA != LS_CTX_SLOT_TP,      "slot collision: rst_pre_va/tp");
_Static_assert(LS_CTX_SLOT_RST_PRE_VA != LS_CTX_SLOT_ALPN,    "slot collision: rst_pre_va/alpn");
_Static_assert(LS_CTX_SLOT_RST_PRE_VA != LS_CTX_SLOT_PARSE,   "slot collision: rst_pre_va/parse");

/* Slot 8 against all eight predecessors. The pairwise list is O(n^2) and is starting to
 * show it --- worth replacing with a designated-initialiser table if a tenth slot
 * arrives, since a duplicate index there is a compile error too and costs one line per
 * slot instead of n. Kept pairwise for now because changing the mechanism and adding a
 * slot in the same edit is how the thing being guarded slips through. */
_Static_assert(LS_CTX_SLOT_SSLERR != LS_CTX_SLOT_SHIELD,     "slot collision: sslerr/shield");
_Static_assert(LS_CTX_SLOT_SSLERR != LS_CTX_SLOT_TP,         "slot collision: sslerr/tp");
_Static_assert(LS_CTX_SLOT_SSLERR != LS_CTX_SLOT_RST_PRE_VA, "slot collision: sslerr/rst_pre_va");
_Static_assert(LS_CTX_SLOT_SSLERR != LS_CTX_SLOT_RST_PRE,    "slot collision: sslerr/rst_pre");
_Static_assert(LS_CTX_SLOT_SSLERR != LS_CTX_SLOT_ALPN,       "slot collision: sslerr/alpn");
_Static_assert(LS_CTX_SLOT_SSLERR != LS_CTX_SLOT_RST,        "slot collision: sslerr/rst");
_Static_assert(LS_CTX_SLOT_SSLERR != LS_CTX_SLOT_RST_VA,     "slot collision: sslerr/rst_va");
_Static_assert(LS_CTX_SLOT_SSLERR != LS_CTX_SLOT_PARSE,      "slot collision: sslerr/parse");

/* And that it FITS. A slot number the trampoline never expanded is refused at arm time
 * by ls_arm.c, but that is a run-time discovery of a build-time mistake. */
_Static_assert(LS_CTX_SLOT_SSLERR < 12,
               "slot >= the 12 LS_TRAMP expansions in trampoline_x86_64.S --- expand it");

#endif /* LS_SLOTS_H */
