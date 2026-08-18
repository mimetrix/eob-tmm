/* tmm:ssl:err --- why the TLS handshake or record layer failed, from TMM's own source.
 *
 * THE TLS TWIN OF rst_why, and the resemblance is structural rather than an analogy:
 *
 *     #define ssl_err(sc, a, ...) ssl__err(sc, a, __func__, __LINE__, __VA_ARGS__)
 *
 *     err_t ssl__err(struct ssl_ctx *sc, enum ssl_alert alert,
 *                    const char *func, int line, ...);
 *
 * A macro that captures the source location, an attributed reason, and a
 * human-written message --- at 475 call sites across seven files:
 *
 *     ssl_hs.c 245 · ssl_hs_tls13.c 88 · ssl_codec.c 77 · ssl.c 39 · ssl_exts.c 20
 *
 * WHAT NOTHING ELSE CAN SEE, stated as the test the previous tracepoint FAILED. The
 * first HTTP tracepoint was rolled back because iRules already observed every field it
 * captured. This one passes that test: an iRule sees CLIENTSSL_HANDSHAKE fail and does
 * not see WHY. Nor does the alert code alone help --- 210 of the 475 sites pass
 * SSL_A_INTERNAL_ERROR and 110 pass SSL_A_ILLEGAL_PARAM, so the alert on the wire
 * distinguishes almost nothing. The diagnosis is the SITE plus the MESSAGE, and that
 * pair exists only inside TMM.
 *
 * Alert codes across the 475 sites, measured from the tree:
 *
 *     internal_error 210 · illegal_parameter 110 · handshake_failure 63
 *     unexpected_message 20 · certificate_unknown 12 · protocol_version 7
 *
 * NO __FILE__, WHICH CHANGES WHAT IDENTIFIES A SITE. rst_why passes __FILE__ and
 * __LINE__; ssl_err passes __func__ and __LINE__. So the function name is what locates
 * the record among seven files, and func[] is sized accordingly --- see the budget note
 * below. A truncated function name plus a line number is still unambiguous in practice,
 * but the field is deliberately the generous one.
 *
 * 97% OF MESSAGES ARE COMPLETE. It is a varargs call and the message is the FIRST
 * vararg, so what arrives in r8 is the format string, not the formatted text. Measured
 * across the tree: 462 of 475 sites (97%) pass a plain literal with no % directive, so
 * for those the captured string IS the whole message. Three sites (1%) pass a real
 * format and we capture the format; ten pass something that is not a literal at all.
 * ssl__err itself vsnprintf()s into the global ssl_msgbuf, so the interpolated text
 * exists --- but only AFTER entry, which an entry hook cannot see.
 *
 * VARARGS CAVEAT, the same one ls_slots.h records for rst_why_va: trampoline_x86_64.S
 * does not save xmm0-15. A varargs call site may have passed floating-point arguments
 * there with rax as the vector count. uBPF's generated code does not touch SSE today,
 * but that is a property of today's uBPF rather than a guarantee. A clobber would
 * corrupt the FORMATTED text downstream, not this record.
 *
 * THE COOKIE IS THE SAME COOKIE. rst_why receives a uflow and ls_flow_cookie.c calls
 * UFLOW_COOKIE(uf). ssl__err receives a struct ssl_ctx, whose `cf` member is a
 * connflow --- and UFLOW_COOKIE expands to CONNFLOW_COOKIE(cf_) for a connflow uflow.
 * So both records carry the SAME value for the same connection, and a TLS failure can
 * be correlated with the reset that followed it. For a streamflow (an HTTP/2 stream)
 * UFLOW_COOKIE additionally XORs the streamflow pointer, so the two differ there ---
 * stated because a correlation that silently works on 1.x and not on h2 is worse than
 * one whose limits are known.
 *
 * DISCLOSURE, as for the reset record: func[] is TMM's own __func__ and lineno is its
 * own source line. Internal identifiers in a telemetry stream are fine inside a closed
 * F5 loop; it is a decision, not a detail, if these records ever leave.
 */
#ifndef LS_CTX_SSLERR_H
#define LS_CTX_SSLERR_H

/*
 * THE BUDGET, and the ceiling is MEASURED rather than inherited as folklore.
 * PREVAIL refuses a ctx access past 96 bytes --- verified 2026-08-18 by compiling
 * programs that read the LAST byte of ctx structs from 64 to 256 bytes: reading byte
 * 95 of a 96-byte ctx passes, byte 99 of a 100-byte ctx fails with
 *
 *     Upper bound must be at most 96 (valid_access(r1.offset+99, width=1) for read)
 *
 * An earlier test that only read byte 0 passed at every size, which proves nothing ---
 * the bound is on the ACCESS, not the declared struct. So this record uses the full 96.
 *
 * Six 32-bit fields keep the alignment at 4 (a 64-bit member would round the size up)
 * and leave 72 bytes for the two strings. Sizes chosen from the measured distribution
 * across all 475 call sites rather than from taste:
 *
 *     __func__  max 36, p95 31, median 16  ->  func[32] truncates 21 sites (4.4%)
 *     message   max 150, p95 49, median 20  ->  msg[40] truncates 52 sites (11.2%)
 *
 * Truncation is recorded, not hidden: func_len and msg_len hold the number of bytes
 * actually copied, so a value of MAX-1 tells a consumer the string was cut. That is
 * the same convention as ls_ctx_rst.h.
 */
#define LS_SSLERR_FUNC_MAX 32u
#define LS_SSLERR_MSG_MAX  40u

struct ls_ctx_sslerr {
    /* Split into two 32-bit halves for the reason ls_ctx_rst.h gives: as a uint64_t
     * the struct's alignment becomes 8 and sizeof rounds up past the ceiling. Zero
     * means NO FLOW, which is legitimate --- ssl__err can fire before a connflow is
     * attached. Reassemble as ((uint64)cookie_hi << 32) | cookie_lo. */
    unsigned int cookie_lo;
    unsigned int cookie_hi;
    unsigned int lineno;      /* __LINE__ of the ssl_err that fired            */
    unsigned int alert;       /* enum ssl_alert --- the TLS AlertDescription   */
    unsigned int func_len;    /* bytes of func[] copied; MAX-1 means truncated */
    unsigned int msg_len;     /* bytes of msg[]  copied; MAX-1 means truncated */
    char         func[LS_SSLERR_FUNC_MAX];  /* __func__, NOT __FILE__          */
    char         msg[LS_SSLERR_MSG_MAX];    /* the first vararg                */
};

/* The alert codes worth naming, because these three account for 383 of 475 sites and
 * a consumer that renders them is far more useful than one printing a bare integer.
 * Values are the TLS AlertDescription wire numbers. */
#define LS_SSL_A_HANDSHAKE_FAILURE 40u
#define LS_SSL_A_ILLEGAL_PARAM     47u
#define LS_SSL_A_INTERNAL_ERROR    80u

/*
 * Build the record from ssl__err's arguments.
 *
 * Every field is a direct argument except the cookie, which is derived from `sc` by
 * ls_ssl_cookie() in the ssl module's include world --- the same split ls_flow_cookie.c
 * uses for rst_why, and for the same reason: CONNFLOW_COOKIE needs TMM's flow types and
 * this header is included by STDINC code.
 *
 * `func` is __func__ and `msg` is a string literal at 97% of sites, so neither is NULL
 * in practice --- guarded anyway and guarded SEPARATELY, because these are two
 * independent pointers and one being NULL must not cost us the other. A tracepoint that
 * faults is worse than one that reports nothing, and this runs on an error path where
 * state is already unusual.
 *
 * No strlen/strncpy: this header is included by ls_tramp.c and must not depend on which
 * include world it lands in.
 */
static inline void
ls_ctx_sslerr_build(struct ls_ctx_sslerr *c, unsigned int alert,
                    const char *func, unsigned int lineno, const char *msg,
                    unsigned long long cookie)
{
    unsigned int i, n;

    c->cookie_lo = (unsigned int)(cookie & 0xffffffffu);
    c->cookie_hi = (unsigned int)(cookie >> 32);
    c->lineno    = lineno;
    c->alert     = alert;
    c->func_len  = 0;
    c->msg_len   = 0;
    for (i = 0; i < LS_SSLERR_FUNC_MAX; i++)
        c->func[i] = 0;
    for (i = 0; i < LS_SSLERR_MSG_MAX; i++)
        c->msg[i] = 0;

    if (func != 0) {
        for (n = 0; n < LS_SSLERR_FUNC_MAX - 1 && func[n] != '\0'; n++)
            c->func[n] = func[n];
        c->func_len = n;
    }

    /* No basename walk, unlike the reset record. __func__ is a bare identifier with no
     * path in it, so scanning for '/' would be pure ceremony. */
    if (msg != 0) {
        for (n = 0; n < LS_SSLERR_MSG_MAX - 1 && msg[n] != '\0'; n++)
            c->msg[n] = msg[n];
        c->msg_len = n;
    }
}

#endif /* LS_CTX_SSLERR_H */
