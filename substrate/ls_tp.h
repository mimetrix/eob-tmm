/* ls_tp.h --- the tracepoint boundary crossing.
 *
 * TMM compiles in two include worlds. Files marked STDINC in src/compile/filelist
 * get the standard C library; files without it get TMM's -nostdinc universe. The
 * VM (ls_vm.c) lives in the first. Every file in modules/hudfilter/http lives in
 * the second. A tracepoint placed in TMM's own logic therefore has to cross.
 *
 * This header is the whole crossing, and it is deliberately dependency-free: it
 * declares one function using only types that are ABI-identical on both sides.
 * `unsigned long` is size_t on x86_64 LP64, so the STDINC side can forward it to
 * ls_vm_call(int, void *, size_t) with no conversion. Nothing else crosses.
 *
 * DO NOT "simplify" this by redeclaring ls_vm_call's real prototype on the
 * -nostdinc side. That is the same mistake ls_prep.c documents: an enum return
 * is not an int return, `bool` comes back in al while `int` reads eax, and the
 * upper bits are not guaranteed. It is an ABI mismatch, not a style question.
 */
#ifndef LS_TP_H
#define LS_TP_H

/* ONE SCHEMA, THREE HOOKS. struct http_parse_info is shared by all three HTTP
 * implementations --- http/ (1.x), http2/ and http3/ all fill ci->http --- so the
 * 40-byte record shape is identical and only the call site differs. The hook id
 * is what tells a consumer which protocol produced a record, and which fields of
 * it are load-bearing:
 *
 *   HTTP/1.x   version, method, header_count, body_pos, hdr_bytes, err
 *   HTTP/2,3   the five f_invalid_* pseudo-header bits (invalid_flags)
 *
 * Those bits are set ONLY by http2/ and http3/ code --- struct http_parse_info
 * documents them as "HTTP/2 pseudo-headers are invalid". On the 1.x path they
 * are never written, so invalid_flags there is uninitialised and must not be
 * read. It is kept in the record rather than dropped precisely because it is the
 * right field the moment an h2 or h3 call site lands. */
#define LS_TP_HOOK_HTTP1_HDRS  1u
#define LS_TP_HOOK_HTTP2_HDRS  2u      /* http2_stream_process_ingress_headers  */
#define LS_TP_HOOK_HTTP3_HDRS  3u      /* http3_process_stream_ingress_headers  */
#define LS_TP_HOOK_RST         4u      /* rst_why --- connection teardown       */

/* Bumped 1 -> 2 with ts_ns. A consumer built against schema 1 walks records at
 * the wrong stride now, so it must fail rather than decode plausible garbage. */
#define LS_TP_SCHEMA_HTTP      2u
#define LS_TP_SCHEMA_RST       1u      /* struct ls_ctx_rst, 64 bytes           */

/*
 * Run the slot's program over `rec`, publish the same bytes to the ring, and
 * return the verdict.
 *
 * RETURNS THE VERDICT, unlike the void ls_tp_emit it replaces. That function
 * existed for the designed-in HTTP call site, which was rolled back on
 * 2026-08-16 as redundant --- iRules already read every field it captured. What
 * remains is entry-armed hooks reached through the trampoline, and those need
 * the verdict: a shield's whole purpose is to act on it.
 *
 * The structural guarantee moves rather than disappearing. A tracepoint is now a
 * hook whose program always returns LS_FALLTHROUGH and whose slot is in MONITOR;
 * it cannot alter traffic because it never selects, not because the plumbing
 * discards the answer. That is weaker than the old void return and is the
 * honest cost of having one path instead of two.
 *
 * Publishing happens AFTER the program runs, deliberately: the program may write
 * to the record, and a consumer should see what the program left rather than a
 * pre-program copy that disagrees with the counters.
 *
 * Safe to call from any TMM thread at any point: it does not allocate, does not
 * lock, does not enter the kernel, and falls through when the slot is empty.
 */
int ls_tp_dispatch(int slot, const void *rec, unsigned long len,
                   unsigned int hook_id);

/*
 * Slot assignment. Slot 0 is the shield --- the built-in program compiled into
 * the binary, and whatever replaces it over the loader socket. Tracepoints get
 * their own slots so that arming or revoking a shield never disturbs telemetry,
 * and so a STATUS query can report them independently (ls_vm_load.c takes the
 * slot from the request rather than assuming 0).
 */
#define LS_TP_SLOT_HTTP_HDRS 1   /* retired --- the designed-in HTTP site is gone */

#endif /* LS_TP_H */
