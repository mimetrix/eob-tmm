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
 * HTTP event ever fired --- there is no request object to hand it. WASM has the
 * same gap for the same reason: both surfaces are built on the parsed model, and
 * this is precisely the traffic that never reached it.
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
 * AND IT NEEDS NO F5 SOURCE EDIT. rst_why is armed at its function entry like a
 * shield, not called from a designed-in site like the HTTP tracepoint. Every field
 * is a direct ARGUMENT --- no derivation, no snapshot timing, nothing overwritten
 * by the time we look. That is why this one is cheap where ALPN was not.
 *
 * THE SIXTH ARGUMENT IS MISSING, and it is the nicest one. rst_cause --- the
 * human-written string, "HTTP header count exceeded by client" --- is argument six,
 * which System V passes in r9. trampoline_x86_64.S saves r9 but forwards only five
 * arguments to ls_tramp_dispatch, because a sixth would land on the stack. So the
 * record carries file:line instead, which identifies the call site uniquely and
 * from which the cause string is recoverable offline from the source. Forwarding
 * the sixth argument is a small change to the trampoline and is not done.
 *
 * DISCLOSURE. file[] is TMM's own __FILE__ --- internal source paths and line
 * numbers in the telemetry stream. Fine for a closed loop inside F5; it is a
 * decision, not a detail, if these records ever leave.
 */
#ifndef LS_CTX_RST_H
#define LS_CTX_RST_H

#define LS_RST_FILE_MAX 48u

/* 64 bytes, inside PREVAIL's 96-byte fentry ctx (LIMITATIONS.md 1.3). */
struct ls_ctx_rst {
    unsigned int lineno;        /* __LINE__ of the RST_WHY that fired        */
    unsigned int err;           /* err_t; ERR_UNKNOWN(32) when unattributed  */
    unsigned int reason;        /* reason code, 0 for the plain RST_WHY form */
    unsigned int file_len;      /* bytes of file[] used, 0 if unavailable    */
    char         file[LS_RST_FILE_MAX];
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
                 unsigned int err, unsigned int reason)
{
    unsigned int i, start = 0, n = 0;

    c->lineno   = lineno;
    c->err      = err;
    c->reason   = reason;
    c->file_len = 0;
    for (i = 0; i < LS_RST_FILE_MAX; i++)
        c->file[i] = 0;

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
