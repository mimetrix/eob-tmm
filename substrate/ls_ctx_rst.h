/* tmm:net:reset --- why TMM tore down this connection, from TMM's own source.
 *
 * WHAT NOTHING ELSE CAN SEE. rst_why() is where every connection reset in TMM is
 * attributed:
 *
 *     rst_why(uf, __FILE__, __LINE__, err, reason, rst_cause)
 *
 * Eighty call sites on the HTTP path alone, each passing the file and line of the
 * decision plus a human-written cause. A client observes a bare TCP reset. An
 * iRule observes nothing at all when the reset follows a failed parse, because no
 * HTTP event ever fired --- there is no request object to hand it. That is checkable:
 * tclrule.c defines the event set, and even where an event exists it need not carry a
 * reason (CLIENTSSL_HANDSHAKE_FAILED is raised with the node and flow and nothing else).
 *
 * NO CLAIM IS MADE ABOUT WASM. It appears nowhere in TMM's source tree, filelist, build
 * configuration or component manifest --- the only WASM mention in the tree used to be
 * this comment. Asserting what a surface cannot see, when the surface is not there, is
 * not an argument.
 *
 * TMM does keep these internally, in a small rst_info_buf ring that overwrites and
 * is not correlated to the request that caused it. What this adds is a per-event
 * record, in order, with the source location, streamed off-box.
 *
 * WHY THIS HOOK RATHER THAN THE HTTP ONE. The first tracepoint sat at
 * http_process_client_headers and captured method, version and header_count on
 * successfully parsed requests --- 21 of 25 records in a sample. An iRule can read
 * every one of those. Only the 4 rejected records were unique. This hook inverts
 * that ratio: every record is a decision no config-level surface can observe.
 *
 * AND IT INSERTS NO CALL SITE. rst_why is armed at its function entry like a shield,
 * not called from a designed-in site like the HTTP tracepoint --- so no existing F5
 * function body is edited for it. (The tree still gains the substrate's own files and
 * three build-configuration edits; "no F5 source edit" was the looser phrasing.) Every field
 * is a direct ARGUMENT --- no derivation, no snapshot timing, nothing overwritten
 * by the time we look. That is why this one is cheap where ALPN was not.
 *
 * THE SIXTH ARGUMENT IS NOW FORWARDED, and it is the nicest one. rst_cause --- the
 * human-written string --- is argument six, which System V passes in r9. The
 * trampoline always SAVED r9; it forwarded only five arguments because rdi carried
 * the slot and a sixth would have landed on the stack. It now passes a POINTER to
 * the whole saved register block instead, so all six arrive and no future signature
 * change touches the asm again. That is fewer instructions than before: one leaq
 * replaced five movq.
 *
 * WHY IT WAS WORTH DOING. file:line identifies the call site, and the cause string
 * is recoverable from the source offline --- so this looked like a nicety. Then
 * flow_table.c:2618 turned up in live records:
 *
 *     RST_WHY_CF(&cf_static, flow_reject_cause[flow_reject_code]);
 *
 * Its cause is not a literal, it is a TABLE LOOKUP. The line number identifies one
 * site while the actual reason is whichever of the enumerated causes applied, and
 * that is exactly the field someone asking "why was this flow rejected" needs. No
 * amount of reading the source recovers it, because the answer is chosen at runtime.
 *
 * THE CTX BUDGET IS WHY file[] SHRANK. PREVAIL admits at most 96 bytes of fentry
 * ctx, the record was 64, and the cause needed room. file[] was 48 bytes for
 * basenames whose longest observed value is "http_mr_proxy.c" at 15, so it is now
 * 32 --- still double the longest real name --- and the record is 92 bytes.
 *
 * DISCLOSURE. file[] is TMM's own __FILE__ --- internal source paths and line
 * numbers in the telemetry stream. Fine for a closed loop inside F5; it is a
 * decision, not a detail, if these records ever leave.
 */
#ifndef LS_CTX_RST_H
#define LS_CTX_RST_H

#define LS_RST_FILE_MAX  28u
#define LS_RST_CAUSE_MAX 36u

/* Still 92 bytes after adding the flow cookie: file[] 32->28 and cause[] 40->36 paid
 * for it. Longest observed basename is "http_mr_proxy.c" (15) and longest common
 * cause is "TCP RST from remote system" (26), so both keep margin.
 * Inside PREVAIL's 96-byte fentry ctx (LIMITATIONS.md 1.3). check_rst.c
 * asserts the ceiling, so growing either array past it fails the build rather than
 * failing verification later with "Upper bound must be at most 96". */
struct ls_ctx_rst {
    /* TMM's flow cookie, SPLIT INTO TWO 32-BIT HALVES on purpose. As a uint64_t the
     * struct's alignment becomes 8, so sizeof rounds 92 up to 96 --- landing exactly
     * on PREVAIL's ceiling with no margin. Two uint32s keep the alignment at 4 and
     * the size at 92. Programs also read 4-byte fields more comfortably.
     * Reassemble as ((uint64)cookie_hi << 32) | cookie_lo. Zero means NO FLOW,
     * which is legitimate --- see ls_flow_cookie.c. */
    unsigned int cookie_lo;
    unsigned int cookie_hi;
    unsigned int lineno;        /* __LINE__ of the RST_WHY that fired        */
    unsigned int err;           /* err_t; ERR_UNKNOWN(32) when unattributed  */
    unsigned int reason;        /* reason code, 0 for the plain RST_WHY form */
    unsigned int file_len;      /* bytes of file[] used, 0 if unavailable    */
    unsigned int cause_len;     /* bytes of cause[] used, 0 if unavailable   */
    char         file[LS_RST_FILE_MAX];
    char         cause[LS_RST_CAUSE_MAX];   /* rst_why's 6th argument        */
};

/* err_t values that matter here. Plain RST_WHY passes ERR_UNKNOWN, so anything
 * else means TMM attributed a specific cause to the teardown. */
#define LS_ERR_EXPIRED  15u
#define LS_ERR_REJECT   16u
#define LS_ERR_UNKNOWN  32u

/*
 * Build the record from rst_why's arguments.
 *
 * Only the BASENAME of file is kept: __FILE__ expands to a long build-relative
 * path, the interesting part is at the end, and 48 bytes is the budget. Copying
 * from the front would keep "./src/modules/hudfilter/" for every record and
 * truncate the part that identifies anything.
 *
 * `file` is a string literal in TMM's rodata so it is never NULL in practice ---
 * guarded anyway, because a tracepoint that faults is worse than one that reports
 * nothing, and this runs on a teardown path where state is already unusual.
 */
static inline void
ls_ctx_rst_build(struct ls_ctx_rst *c, const char *file, unsigned int lineno,
                 unsigned int err, unsigned int reason, const char *cause,
                 unsigned long long cookie)
{
    unsigned int i, start = 0, n = 0;

    c->cookie_lo = (unsigned int)(cookie & 0xffffffffu);
    c->cookie_hi = (unsigned int)(cookie >> 32);
    c->lineno    = lineno;
    c->err       = err;
    c->reason    = reason;
    c->file_len  = 0;
    c->cause_len = 0;
    for (i = 0; i < LS_RST_FILE_MAX; i++)
        c->file[i] = 0;
    for (i = 0; i < LS_RST_CAUSE_MAX; i++)
        c->cause[i] = 0;

    /* The cause first, and guarded separately from file. These are two independent
     * pointers from a teardown path: one being NULL must not cost us the other. */
    if (cause != 0) {
        for (n = 0; n < LS_RST_CAUSE_MAX - 1 && cause[n] != '\0'; n++)
            c->cause[n] = cause[n];
        c->cause_len = n;
    }
    n = 0;

    if (file == 0)
        return;

    /* Find the basename, bounded. No strlen/strrchr: this header is included by
     * ls_tramp.c and must not depend on which include world it lands in. */
    for (i = 0; i < 256u && file[i] != '\0'; i++) {
        if (file[i] == '/')
            start = i + 1;
    }
    for (n = 0; n < LS_RST_FILE_MAX - 1 && file[start + n] != '\0'; n++)
        c->file[n] = file[start + n];
    c->file_len = n;
}

#endif /* LS_CTX_RST_H */
