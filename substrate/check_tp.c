/* Does the tracepoint record survive contact with a compiler, and do the host
 * and program agree on its layout?
 *
 * WHAT THIS PROVES AND WHAT IT CANNOT. ls_tp_http.h is a static inline compiled
 * inside http1x.c, in TMM's -nostdinc world, against TMM's real structs. None of
 * that exists here. So this file supplies MOCK structs with the same field names
 * and shapes read from the real headers, and checks the things that are checkable
 * off the build box:
 *
 *   - the record is exactly 40 bytes, and matches the program's copy
 *   - the builder compiles, with every field written
 *   - the pcb and hd null guards actually guard (a null hd yields a zeroed
 *     record carrying the verdict, not a fault)
 *   - the five f_invalid_* bits compose into the flags word by NAME
 *
 * It CANNOT prove the field names match TMM's. Only the TMM build does that ---
 * and that is the point of composing by name rather than by byte offset: a
 * rename fails the build there instead of returning wrong bits at runtime. The
 * mock is a syntax and layout gate, not a substitute for compiling in the tree.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ---- mock TMM types, mirroring the real headers in modules/hudfilter/http --------------- */
typedef unsigned char  BYTE;
typedef unsigned short UINT16;
typedef unsigned int   UINT32;
typedef int            BOOL;

struct tm_header_cache { int opaque; };

struct http_parse_info {              /* http_parser.h --- __PACKED there */
    BOOL is_trailer : 1;
    BOOL is_request : 1;
    BOOL is_crlf : 1;
    BOOL lws_found : 1;
    unsigned version : 2;
    unsigned original_version : 2;
    BYTE method;
    UINT16 header_count;
    UINT32 body_pos;
    int status_code;
    UINT32 f_invalid_method    : 1;
    UINT32 f_invalid_scheme    : 1;
    UINT32 f_invalid_path      : 1;
    UINT32 f_invalid_status    : 1;
    UINT32 f_invalid_authority : 1;
    UINT32 reserved            : 27;
    struct tm_header_cache cache;
};

struct xbuf { UINT32 len; };

struct http_header_cache_info {       /* http.h */
    struct xbuf xb_hdrs;
    struct http_parse_info http;
};

struct hud_ref { int opaque; };

struct http_data {                    /* http.h --- ci is EMBEDDED, not a pointer */
    struct hud_ref ref;
    struct http_header_cache_info ci;
};

enum http1x_reject_reason {           /* http1x.h */
    HTTP1X_REJECT_UNKNOWN = 0,
    HTTP1X_REJECT_METHOD,
    HTTP1X_REJECT_HEADER_SIZE,
    HTTP1X_REJECT_HEADER_NUMBER,
    HTTP1X_REJECT_HEADER_CRNL,
};

struct http1x_pcb {
    struct http_data *hd;
    enum http1x_reject_reason reject_reason : 4;
};

/* ---- the crossing, captured instead of forwarded ------------------------ */
static struct { int slot; unsigned long len; unsigned char rec[64]; int calls; } g_emit;

#define LS_TP_SLOT_HTTP_HDRS 1
static void
ls_tp_emit(int slot, const void *rec, unsigned long len)
{
    g_emit.slot = slot;
    g_emit.len  = len;
    if (len <= sizeof g_emit.rec)
        memcpy(g_emit.rec, rec, len);
    g_emit.calls++;
}

#include "ls_tp_http.h"

/* The program's copy, renamed so both layouts exist in one translation unit and
 * a divergence is a compile-time failure rather than a runtime surprise. */
#define ls_tp_http_hdrs ls_tp_http_hdrs_prog
#define LS_TP_HTTP_H_GUARD_UNUSED
#include "shields/ls_tp_http_bpf.h"
#undef ls_tp_http_hdrs

int
main(void)
{
    struct http_parse_info *pi;
    struct http_data hd;
    struct http1x_pcb pcb;
    const struct ls_tp_http_hdrs *r;
    int n = 0;

    /* 1. layout, both sides */
    assert(sizeof(struct ls_tp_http_hdrs) == 40);                              n++;
    assert(sizeof(struct ls_tp_http_hdrs) == sizeof(struct ls_tp_http_hdrs_prog)); n++;

    /* 2. a clean request: verdict recorded, nothing flagged */
    memset(&hd, 0, sizeof hd);
    memset(&pcb, 0, sizeof pcb);
    pcb.hd = &hd;
    pi = &hd.ci.http;
    pi->version      = 1;
    pi->method       = 3;
    pi->header_count = 7;
    pi->body_pos     = 128;
    hd.ci.xb_hdrs.len = 256;

    g_emit.calls = 0;
    ls_tp_http_hdrs_emit(pcb.hd, 0, 0, (int)pcb.reject_reason);
    assert(g_emit.calls == 1);                                                 n++;
    assert(g_emit.slot == LS_TP_SLOT_HTTP_HDRS);                               n++;
    assert(g_emit.len == 40);                                                  n++;

    r = (const struct ls_tp_http_hdrs *)g_emit.rec;
    assert(r->version == 1 && r->method == 3 && r->header_count == 7);         n++;
    assert(r->body_pos == 128 && r->hdr_bytes == 256);                         n++;
    assert(r->invalid_flags == 0 && r->reject_reason == 0);                    n++;

    /* 3. each violation bit composes to its own flag, BY NAME. If a field is
     *    renamed upstream this block stops compiling --- which is the entire
     *    reason it is written this way instead of masking a byte offset. */
    pi->f_invalid_method = 1;
    ls_tp_http_hdrs_emit(pcb.hd, 0, 0, (int)pcb.reject_reason);
    assert(r->invalid_flags == LS_TP_INVALID_METHOD);                          n++;
    pi->f_invalid_method = 0; pi->f_invalid_authority = 1;
    ls_tp_http_hdrs_emit(pcb.hd, 0, 0, (int)pcb.reject_reason);
    assert(r->invalid_flags == LS_TP_INVALID_AUTHORITY);                       n++;
    pi->f_invalid_path = 1;
    ls_tp_http_hdrs_emit(pcb.hd, 0, 0, (int)pcb.reject_reason);
    assert(r->invalid_flags == (LS_TP_INVALID_AUTHORITY | LS_TP_INVALID_PATH)); n++;
    pi->f_invalid_authority = 0; pi->f_invalid_path = 0;

    /* 4. a rejected request carries the reason --- the field the whole
     *    tracepoint exists for, and the one an entry hook could never see
     *    because the functions that set it are inlined away. */
    pcb.reject_reason = HTTP1X_REJECT_METHOD;
    ls_tp_http_hdrs_emit(pcb.hd, 5, 0, (int)pcb.reject_reason);
    assert(r->reject_reason == (unsigned)HTTP1X_REJECT_METHOD);                n++;
    assert(r->err == 5);                                                       n++;

    /* 5. THE GUARD. A pcb without http_data must still emit a well-formed
     *    record carrying the verdict --- never fault. A tracepoint that can
     *    crash TMM to observe it is worse than no tracepoint. */
    pcb.hd = 0;
    pcb.reject_reason = HTTP1X_REJECT_HEADER_CRNL;
    g_emit.calls = 0;
    ls_tp_http_hdrs_emit(pcb.hd, 9, 2, (int)pcb.reject_reason);
    assert(g_emit.calls == 1);                                                 n++;
    assert(r->err == 9 && r->passthru == 2);                                   n++;
    assert(r->reject_reason == (unsigned)HTTP1X_REJECT_HEADER_CRNL);           n++;
    assert(r->version == 0 && r->method == 0 && r->header_count == 0 &&
           r->status_code == 0 && r->body_pos == 0 && r->hdr_bytes == 0 &&
           r->invalid_flags == 0);                                             n++;

    /* 6. THE CONTRACT AFTER THE REFACTOR. The builder takes scalars, not a pcb,
     *    so there is no pcb to be null and a record is ALWAYS emitted --- the
     *    verdict is never silently dropped because a pointer was missing. This
     *    is the shape that lets one tracepoint serve both http.c's and
     *    http1x.c's http_process_client_headers, which is what the first version
     *    got wrong by binding to struct http1x_pcb. */
    g_emit.calls = 0;
    ls_tp_http_hdrs_emit(0, 7, 1, 3);
    assert(g_emit.calls == 1);                                                 n++;
    assert(r->err == 7 && r->passthru == 1 && r->reject_reason == 3);          n++;

    printf("ok    ls_tp_http.h  (%d assertions: 40-byte record both sides, flags by "
           "name, null-hd guard)\n", n);
    return 0;
}
