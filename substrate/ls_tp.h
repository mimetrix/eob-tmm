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
/*
 * ONE ID PER RESET FUNCTION. RST_WHY* macros expand to four different functions and
 * every record used to carry LS_TP_HOOK_RST regardless, so a consumer could not tell
 * which one fired --- you had to look the site's macro up in TMM's source, which
 * defeats the purpose for anyone not sitting next to the tree.
 *
 * This is possible only because each function now gets its OWN slot. They shared
 * slots while the trampoline had a single patched slot immediate; per-slot
 * trampolines removed that, and the dispatcher derives the id from the slot.
 *
 * ADDITIVE, NOT A LAYOUT CHANGE. hook_id lives in the ring HEADER (struct ls_rec),
 * not in the 92-byte payload, so LS_TP_SCHEMA_RST stays 3. The drain keeps emitting
 * "hook":"reset" for all four --- a consumer keying on that does not break --- and
 * adds "fn" naming the specific function.
 */
#define LS_TP_HOOK_RST_VA      5u      /* rst_why_va --- varargs form           */
#define LS_TP_HOOK_RST_PRE     6u      /* rst_why_preserve --- 5 args, no reason*/
#define LS_TP_HOOK_RST_PRE_VA  7u      /* rst_why_preserve_va                   */
/* ssl__err --- why the TLS handshake or record layer failed. A DIFFERENT hook family
 * from the reset four, so it gets its own `hook` string in the drain ("sslerr") rather
 * than joining "reset": a consumer filtering on hook must be able to separate "TMM tore
 * the connection down" from "TLS failed", which are different questions with different
 * owners. */
#define LS_TP_HOOK_SSLERR      8u      /* ssl__err --- 475 call sites           */
/* http2_stream_abort --- its own hook family and its own `hook` string ("h2abort"), for
 * the reason sslerr got one: a consumer must be able to separate "an h2 STREAM was
 * aborted" from "the CONNECTION was reset" and from "TLS failed". Three questions, three
 * owners. */
#define LS_TP_HOOK_H2ABORT     9u      /* http2_stream_abort --- 36 call sites   */
/*
 * PROGRAM-EMITTED. Not a hook at all --- the record was published by a program calling
 * bpf_ringbuf_output(), so no hook fired and the host does not know the byte layout.
 *
 * A high number on purpose: hook ids 1-9 name places in TMM, and this names the absence
 * of one. Putting it at 10 would have implied it was the next hook.
 */
#define LS_TP_HOOK_PROG      100u      /* emitted by a program, not by a hook   */

/* Bumped 1 -> 2 with ts_ns. A consumer built against schema 1 walks records at
 * the wrong stride now, so it must fail rather than decode plausible garbage. */
#define LS_TP_SCHEMA_HTTP      2u
/* 2, not 1: Phase 3 added cause[] and shrank file[] from 48 to 32, so a consumer
 * built against schema 1 would read `line` out of the middle of a filename. The
 * version is the only thing standing between a layout change and silently wrong
 * decoded output --- bump it in the SAME edit as the struct, every time. */
#define LS_TP_SCHEMA_RST       3u      /* struct ls_ctx_rst, 92 bytes + cookie  */
/* struct ls_ctx_sslerr, 96 bytes --- AT the measured PREVAIL ctx ceiling, not under it.
 * A distinct schema rather than a variant of 3: the field layout shares nothing with
 * the reset record beyond the cookie, so a consumer must not be able to decode one as
 * the other. That is the whole job of this number. */
#define LS_TP_SCHEMA_SSLERR    4u
/* struct ls_ctx_h2abort, 48 bytes. Distinct from 3 and 4 because the layout shares
 * nothing with either --- no file, no line, no alert, no cookie. */
#define LS_TP_SCHEMA_H2ABORT   5u
/* Program-chosen bytes. The host validated the LENGTH and nothing else, so the drain
 * reports len and hex rather than naming fields it cannot vouch for. */
#define LS_TP_SCHEMA_PROG    100u

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

/* Publish bytes a PROGRAM chose, without running anything. Reached from the
 * bpf_ringbuf_output helper. Separated from ls_tp_dispatch because that function runs
 * the slot's program first, and calling it from a helper the program invoked would
 * re-enter the VM from inside itself. Returns 0, or -1 when the ring is off. */
int ls_tp_publish_raw(int slot, const void *rec, unsigned long len);

/*
 * Slot assignment. Slot 0 is the shield --- the built-in program compiled into
 * the binary, and whatever replaces it over the loader socket. Tracepoints get
 * their own slots so that arming or revoking a shield never disturbs telemetry,
 * and so a STATUS query can report them independently (ls_vm_load.c takes the
 * slot from the request rather than assuming 0).
 */
#define LS_TP_SLOT_HTTP_HDRS 1   /* retired --- the designed-in HTTP site is gone */

/*
 * Hook id -> record schema, in ONE place next to the constants.
 *
 * ls_tp_emit.c used to inline this as `hook_id == LS_TP_HOOK_RST ? RST : HTTP`. A
 * single equality against one id, so the moment the reset family grew to four ids the
 * other three silently mapped to LS_TP_SCHEMA_HTTP. The payload was a correct 92-byte
 * reset record with a schema saying "HTTP", and the drain --- correctly --- refused to
 * decode it and printed raw hex. The producer was wrong, not the consumer.
 *
 * A helper here rather than a ternary there: adding a hook id and forgetting its
 * schema is now one edit away from the constants it must agree with.
 */
static inline unsigned int
ls_tp_schema_for(unsigned int hook_id)
{
    switch (hook_id) {
    case LS_TP_HOOK_RST:
    case LS_TP_HOOK_RST_VA:
    case LS_TP_HOOK_RST_PRE:
    case LS_TP_HOOK_RST_PRE_VA:
        return LS_TP_SCHEMA_RST;
    case LS_TP_HOOK_HTTP1_HDRS:
    case LS_TP_HOOK_HTTP2_HDRS:
    case LS_TP_HOOK_HTTP3_HDRS:
        return LS_TP_SCHEMA_HTTP;
    case LS_TP_HOOK_SSLERR:
        return LS_TP_SCHEMA_SSLERR;
    case LS_TP_HOOK_H2ABORT:
        return LS_TP_SCHEMA_H2ABORT;
    case LS_TP_HOOK_PROG:
        return LS_TP_SCHEMA_PROG;
    default:
        /* An unknown hook must NOT default to a real schema --- that is exactly how a
         * reset record came out labelled HTTP. 0 is not a valid schema, so the
         * consumer rejects it and prints raw rather than misreading the fields. */
        return 0u;
    }
}

#endif /* LS_TP_H */
