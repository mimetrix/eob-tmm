/* tmm:http2:abort --- why TMM aborted this HTTP/2 stream, from TMM's own source.
 *
 *     static void http2_stream_abort(struct http2_stream *stream, const char *why,
 *                                    enum http2_error err);
 *
 * WHY THIS SITE, AND WHAT DISQUALIFIED THE ALTERNATIVE. Four tests decide whether a
 * decision is reachable ONLY by hooking it. Applying the first alone is what made
 * ssl__err look valuable for an afternoon:
 *
 *   1. Is it a DECISION?      yes --- `why` is a human-written reason, 23 distinct
 *                             literals across 36 call sites.
 *   2. Is it ALREADY LOGGED?  NO, and this is the test ssl__err failed. Its only
 *                             narration is TRACES(), which expands to TRACEF(), which
 *                             is inside `#if HTTP2_DEBUG` --- undefined in the shipped
 *                             build. PROVEN FROM THE BINARY rather than from reading
 *                             the source: "initiates ABORT in" occurs 0 times in
 *                             tmm.no_pgo, as does the "HTTP2 [" trace prefix, while
 *                             ssl__err's "Connection error" occurs 4 times.
 *   3. Does an iRULE see it?  no tclrule_execute() in the body.
 *   4. Is it WORTH it?        36 call sites, on a path BNK genuinely runs --- h2 is
 *                             negotiated over ALPN on the lab cluster and serves
 *                             end-to-end (curl --http2 -> "HTTP 404 via 2").
 *
 * NO __FILE__ AND NO __LINE__, unlike rst_why --- and it does not matter here, because
 * `why` IS the site. 23 distinct literals over 36 calls, so the string identifies the
 * decision more directly than a line number would.
 *
 * THE ONE HONEST CAVEAT: http2_stream_abort is `static`. At -O2 the compiler may inline
 * or clone some calls, and an inlined call does not pass through the padded entry. So
 * arming this sees the calls that were emitted as real calls, not necessarily all 36.
 * The build DID emit an out-of-line body with a pad (found at 0xcf4a40, five nops at
 * offset 0 --- no endbr64, because a static is never an indirect-call target), so it is
 * armable; how many of the 36 reach it is a measurement, not an assumption, and must be
 * reported as such.
 */
#ifndef LS_CTX_H2ABORT_H
#define LS_CTX_H2ABORT_H

/* 36 covers the longest observed literal ("frame refused due to header size", 32) with
 * margin. Measured across all 23 literals in http2.c rather than guessed. */
#define LS_H2ABORT_WHY_MAX 36u

/* 48 bytes, deliberately well under PREVAIL's 96-byte ctx ceiling rather than at it.
 * There is nothing else worth carrying: the arguments are a stream, a reason and an
 * error code, and inventing fields to fill the budget would be the opposite of the
 * point. check_h2abort.c asserts the size so a later addition is a build decision. */
struct ls_ctx_h2abort {
    /* AN IDENTITY, NOT AN ADDRESS. Folded from the stream pointer so records can be
     * grouped by stream --- "these six aborts are one stream" versus "six streams" ---
     * without putting a live host address into a telemetry stream. Same reasoning as
     * CONNFLOW_COOKIE, which hashes rather than exposing the connflow pointer.
     *
     * NOT the flow cookie the reset feed carries, and deliberately not called one: the
     * flow is reachable as stream->owner->uf, but that needs the http2 module's include
     * world and a second crossing TU. Deferred rather than approximated --- a field
     * named `flow` that did not join the reset feed would be worse than no field. */
    unsigned int stream_id;
    unsigned int error;        /* enum http2_error --- the HTTP/2 error code sent */
    unsigned int why_len;      /* bytes of why[] copied; MAX-1 means truncated    */
    char         why[LS_H2ABORT_WHY_MAX];
};

/*
 * Build the record from http2_stream_abort's arguments.
 *
 * Every field is a direct argument, so there is no derivation and nothing has been
 * overwritten by the time an entry hook looks --- the property that made the reset hook
 * cheap and the ALPN hook expensive.
 *
 * `why` is a string literal at every observed call site, so it is never NULL in
 * practice. Guarded anyway: this runs on a teardown path where state is already unusual,
 * and a tracepoint that faults is worse than one that reports nothing.
 *
 * No strlen/strncpy --- this header is included by ls_tramp.c and must not depend on
 * which include world it lands in.
 */
static inline void
ls_ctx_h2abort_build(struct ls_ctx_h2abort *c, unsigned long long stream,
                     const char *why, unsigned int error)
{
    unsigned int i, n;

    /* Fold high and low halves together and drop the low bits: allocations are aligned,
     * so the bottom nibble carries no information, and mixing in the high half keeps
     * two streams from colliding merely because they share a page. Not cryptographic
     * and does not need to be --- it answers "same stream or not". */
    c->stream_id = (unsigned int)((stream >> 4) ^ (stream >> 32));
    c->error     = error;
    c->why_len   = 0;
    for (i = 0; i < LS_H2ABORT_WHY_MAX; i++)
        c->why[i] = 0;

    if (why != 0) {
        for (n = 0; n < LS_H2ABORT_WHY_MAX - 1 && why[n] != '\0'; n++)
            c->why[n] = why[n];
        c->why_len = n;
    }
}

#endif /* LS_CTX_H2ABORT_H */
