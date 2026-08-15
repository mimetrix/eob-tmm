/* ls_tp_http.h --- tmm:l7:http_headers, a designed-in tracepoint.
 *
 * WHAT A TRACEPOINT IS, AND WHY THIS IS NOT A HOOK. A tracepoint is a chosen
 * structure exposed at a chosen point in the logic. A patched function entry is
 * something else: it lands wherever a function happens to begin, which is a
 * powerful instrument for debugging and root-cause work on a running system and
 * a poor one for telemetry. Two attempts to build this as an entry hook failed
 * for reasons that were structural, not incidental:
 *
 *   - Entry runs BEFORE the function body. Hooking http_parse_client_headers at
 *     its entry and reading header_count / status_code / the f_invalid_* bits
 *     reads a struct the function has not written yet. Every field came back
 *     zero, which was the correct value, not a bug.
 *   - The interesting failures are unreachable. http1x_psm_method,
 *     http1x_psm_header_count and http1x_psm_header_crnl are defined in
 *     http1x.h, so the compiler folds them into their callers. No symbol, no
 *     entry pad, nothing to arm. Entry patching cannot see inlined code.
 *
 * A deliberate call site has neither problem: it sits after the parse, where the
 * data exists, and inlining is irrelevant because we own the site.
 *
 * WHERE IT SITS --- AND WHY IT TAKES SCALARS, NOT A pcb. There are TWO static
 * functions named http_process_client_headers: one in http1x.c taking
 * struct http1x_pcb *, one in http.c taking struct http_scb *. Both are
 * file-scope, so nothing collides and nothing warns, and both call
 * http_parse_client_headers --- which is why an entry hook on the parser fires
 * for either and cannot tell them apart.
 *
 * The first version of this tracepoint went into the http1x.c one and never
 * fired: 9 requests returned 200 with fired=0. Only http.c's survives as a
 * symbol (addr2line on 0xca5c80 -> http.c:7769), and that is the one this
 * traffic executes.
 *
 * So the builder takes the pieces it needs rather than a pcb, and one
 * tracepoint serves BOTH call sites --- each passing its own reject_reason.
 * Binding to a pcb type would have forced two near-identical builders and a
 * second chance to instrument the wrong one. Both functions converge on a
 * single `return err`, so one call each sees the whole outcome per request.
 *
 * WHAT IT EXPOSES, AND WHY THAT IS NEEDFUL. TMM computes all of this per
 * request and keeps none of it. Today the only trace of a malformed request is
 * a reset and, sometimes, a log line; there is no per-request record that says
 * what was wrong, and no way to count classes of malformation over time.
 *
 * TRIGGERABLE ON DEMAND --- the property the earlier attempts lacked:
 *
 *     curl -X BOGUS            -> err=REJECT  reason=METHOD
 *     200 x -H                 -> err=BOUNDS  reason=HEADER_NUMBER
 *     oversize header          ->             reason=HEADER_SIZE
 *     bare CR/LF (raw socket)  -> err=VAL     reason=HEADER_CRNL
 *     plain GET, --http1.0     -> err=OK      version moves
 *
 * Every row is an input we choose and a field value we predict before running
 * it. A tracepoint that cannot be fired deliberately cannot be validated, which
 * is the same reason the CVE work stalled.
 *
 * INCLUDE DISCIPLINE. This header includes NOTHING and must be included by
 * http1x.c AFTER its own headers. The builder is a static inline compiled in the
 * caller's translation unit, so it inherits that file's include world exactly
 * --- no -I guessing, and no separate object that has to be taught how to find
 * TMM's headers. Only ls_tp_emit() crosses into the STDINC world; see ls_tp.h.
 *
 * PACKED STRUCTS. struct http_parse_info and struct http_header_cache_info are
 * __PACKED. Every read below is BY VALUE through the embedded chain
 * (hd->ci.http.field). Taking the address of a packed member is what
 * ALLOW_ADR_PKD_MEM exists to permit, and this file never needs it.
 */
#ifndef LS_TP_HTTP_H
#define LS_TP_HTTP_H

/*
 * The record. Ten fixed-width scalars, no pointers, no nesting --- the shape a
 * verified eBPF program can read and the shape PREVAIL already proves. `unsigned
 * int` is 32 bits on both the TMM target and the BPF target, so the program's
 * copy of this layout (substrate/shields/ls_tp_http_bpf.h) matches byte for byte
 * and asserts its own size.
 */
struct ls_tp_http_hdrs {
    unsigned int parse_err;      /* THE PARSER'S OWN VERDICT --- see note below     */
    unsigned int err;            /* what the filter finally decided (NOT the parse) */
    unsigned int reject_reason;  /* enum http1x_reject_reason, 0 when not rejected */
    unsigned int passthru;       /* enum http_passthru_reason: which check was waived */
    unsigned int version;        /* hd->ci.http.version      (2-bit field, widened)  */
    unsigned int method;         /* hd->ci.http.method       (BYTE)                  */
    unsigned int header_count;   /* hd->ci.http.header_count (UINT16)                */
    unsigned int status_code;    /* hd->ci.http.status_code  (int)                   */
    unsigned int invalid_flags;  /* HTTP/2+3 ONLY --- see the note below            */
    unsigned int body_pos;       /* hd->ci.http.body_pos: offset to body start       */
    unsigned int hdr_bytes;      /* hd->ci.xb_hdrs.len: header bytes actually seen   */
};

/*
 * TWO VERDICTS, AND THEY ARE NOT THE SAME ONE.
 *
 * `err` at the convergence point is NOT the parse result. Inside
 * http_process_client_headers it is reassigned twelve or more times after the
 * parse --- ERR_ARG on two rejection paths, ERR_OK on several waivers, then the
 * results of http_ingress_initialize, http_header_insert_profiles,
 * format_via_info and http_process_clientside_profile_rules. By the time this
 * record is emitted it reports the LAST thing that happened, not why the request
 * was refused. Every rejected record we captured before this change carried
 * ERR_ARG(4), a value that does not appear anywhere in http_parser.c.
 *
 * So `parse_err` is snapshotted immediately after http_parse_client_headers
 * returns, before any of that. It is the field that answers "why".
 *
 * ERR_MORE_DATA IS NOT A REJECTION, and this is the trap worth naming: it is 17,
 * so a `parse_err != 0` predicate counts every set of headers that spans two
 * packets --- the most ordinary thing HTTP does --- as a fault. Classify with the
 * values below, never with a zero test.
 */
#define LS_ERR_OK          0u
#define LS_ERR_VAL         3u   /* illegal value --- CR/LF in a header      */
#define LS_ERR_BOUNDS      5u   /* out of bounds --- header count exceeded  */
#define LS_ERR_REJECT     16u   /* traffic rejected --- unknown method      */
#define LS_ERR_MORE_DATA  17u   /* NORMAL: headers span packets             */

/*
 * THE THREE CLASSES. They come apart in practice, which is why the record
 * carries the pieces and lets a loaded program choose the predicate:
 *
 *   malformed   parse_err in {VAL, BOUNDS, REJECT}
 *   refused     malformed AND passthru == 0     --- TMM declined to proxy it
 *   waived      malformed AND passthru != 0     --- TMM KNEW and forwarded anyway
 *
 * `waived` is its own class and the most valuable of the three. TMM has
 * passthru_unknown_method, passthru_excess_client_headers and
 * passthru_oversize_client_headers; when one is set, a request TMM has already
 * judged malformed is proxied to the origin, and nothing anywhere records that
 * decision. It is not an error, so no log line fires.
 *
 * Note what is NOT a class: a request the ORIGIN rejects. `curl -X BOGUSMETHOD`
 * returns 501 while parse_err is ERR_OK --- extension methods are legal, TMM
 * forwarded it, and the backend refused. Client-visible failure, zero TMM
 * involvement. Counting those as rejections would be wrong.
 */

/*
 * The five parse-violation bits, composed into one word.
 *
 * These are FIVE SEPARATE BITFIELDS in struct http_parse_info
 * (f_invalid_method, _scheme, _path, _status, _authority) --- not one field. An
 * earlier version of this tracepoint read them through a hardcoded byte offset
 * and a 0x1f mask, which is fragile in the worst way: rename or reorder a field
 * and the mask silently returns a different set of bits. Composing them by NAME
 * means the same change fails to compile.
 */
#define LS_TP_INVALID_METHOD    0x01u
#define LS_TP_INVALID_SCHEME    0x02u
#define LS_TP_INVALID_PATH      0x04u
#define LS_TP_INVALID_STATUS    0x08u
#define LS_TP_INVALID_AUTHORITY 0x10u

/*
 * Build and emit. Called once per request, from the single convergence point.
 *
 * `hd` is guarded rather than assumed: a request that somehow arrives without
 * http_data still emits a well-formed row carrying the verdict instead of
 * faulting. Crashing TMM in order to observe it would be an unusually poor
 * trade. The record is filled unconditionally first, so the verdict is never
 * lost just because a pointer was missing.
 */
/*
 * SNAPSHOT, called immediately after http_parse_client_headers returns. Captures
 * the parser's verdict and the parse info AS THE PARSER LEFT IT --- both are
 * destroyed by the rest of the function.
 */
static inline void
ls_tp_http_hdrs_snap(struct ls_tp_http_hdrs *cp, const struct http_data *hd,
                     int parse_err)
{
    struct ls_tp_http_hdrs c;
    unsigned int i;

    /* No memset(): string.h is not in this include world. Ten explicit stores
     * also mean adding a field to the record without filling it is a visible
     * omission rather than a silent zero. */
    c.parse_err     = (unsigned int)parse_err;
    c.err           = 0;            /* filled at emit, after the filter decides */
    c.reject_reason = 0;
    c.passthru      = 0;
    c.version       = 0;
    c.method        = 0;
    c.header_count  = 0;
    c.status_code   = 0;
    c.invalid_flags = 0;
    c.body_pos      = 0;
    c.hdr_bytes     = 0;

    if (hd != 0) {
        c.version      = (unsigned int)hd->ci.http.version;
        c.method       = (unsigned int)hd->ci.http.method;
        c.header_count = (unsigned int)hd->ci.http.header_count;
        c.status_code  = (unsigned int)hd->ci.http.status_code;
        c.body_pos     = (unsigned int)hd->ci.http.body_pos;
        c.hdr_bytes    = (unsigned int)hd->ci.xb_hdrs.len;

        i = 0;
        if (hd->ci.http.f_invalid_method)    i |= LS_TP_INVALID_METHOD;
        if (hd->ci.http.f_invalid_scheme)    i |= LS_TP_INVALID_SCHEME;
        if (hd->ci.http.f_invalid_path)      i |= LS_TP_INVALID_PATH;
        if (hd->ci.http.f_invalid_status)    i |= LS_TP_INVALID_STATUS;
        if (hd->ci.http.f_invalid_authority) i |= LS_TP_INVALID_AUTHORITY;
        c.invalid_flags = i;
    }

    *cp = c;
}

/*
 * EMIT, at the single convergence point every path reaches. Adds what the filter
 * decided to what the parser found, then publishes.
 */
static inline void
ls_tp_http_hdrs_emit(struct ls_tp_http_hdrs *cp, int err, int passthru,
                     int reject_reason)
{
    cp->err           = (unsigned int)err;
    cp->passthru      = (unsigned int)passthru;
    cp->reject_reason = (unsigned int)reject_reason;
    ls_tp_emit(LS_TP_SLOT_HTTP_HDRS, cp, (unsigned long)sizeof *cp);
}

#endif /* LS_TP_HTTP_H */
