/* SHIELD --- CVE-2025-41414 / BZ1496457, LTM_HTTP2, CWE-476.
 *
 * THE DEFECT. Fix 81d3428d3d added a NULL check that this build has reverted:
 *     -    HTTP2_FRAME_FLAG_SET(frame, END_HEADERS);       // frame may be NULL
 *     +    if (frame != NULL) { HTTP2_FRAME_FLAG_SET(frame, END_HEADERS);
 * `frame` is NULL when the HPACK-serialised header block comes out empty.
 * http2_from_http_data always writes at least one byte for a non-trailer --- :status
 * for a response, the 0x87 scheme for a request --- so the empty case is reachable
 * ONLY through a trailer, and only one carrying no headers. Reproduced with a single
 * client request: SIGSEGV, fault address 0x13 (NULL + 0x13), core dumped.
 *
 * WHY THIS FILE EXISTS IN THE REPO AT ALL, which is the lesson. The original
 * demonstration's shield lived in a scratch directory, and so did the HTTP/2 origin
 * that triggered it. Both vanished with the session, and on 2026-09-05 the headline
 * result of this project could not be re-run from the repository. The origin is now
 * env/k8s/h2-trailer-backend.yaml; this is the other half.
 *
 * THE PREDICATE IS A DELIBERATE OVER-APPROXIMATION, and saying so is the point.
 * The true condition is "the serialised header block is empty" --- a local (xb.len)
 * that an ENTRY hook cannot see. What is visible at entry is the shape of the
 * response being framed:
 *
 *     end_stream == 1 && push == 0 && status_code != 0
 *
 * which matches a bodyless response framing. That is a SUPERSET of the crashing
 * case. Measured 10/10 on the known-positive and 0/10 false positives, but 0/10 is
 * measured, not proven-zero, and the difference matters: a false positive here
 * substitutes a safe return for a frame that would have been fine.
 */
typedef unsigned int __u32; typedef unsigned long long __u64;
static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

/* Only the fields read, declared with preserve_access_index so the offsets are
 * resolved against the target build rather than guessed. */
struct http_ci_http { __u32 status_code; } __attribute__((preserve_access_index));
struct http_ci      { struct http_ci_http http; } __attribute__((preserve_access_index));
struct http_data    { struct http_ci ci; } __attribute__((preserve_access_index));
struct http2_stream { void *http_data; } __attribute__((preserve_access_index));

struct ls_ctx_generic { __u64 arg[5]; };
#define LS_SAFE_RETURN 1ull
#define LS_FALLTHROUGH 0ull

__attribute__((section("fentry/http2_http_data_to_frames"), used))
__u64 h2_trailer_guard(struct ls_ctx_generic *c)
{
    /* arg[2] = end_stream, arg[3] = push. Both are scalars in the ctx, so no read
     * is needed and no relocation applies to them. */
    if (c->arg[2] != 1ull || c->arg[3] != 0ull)
        return LS_FALLTHROUGH;

    struct http2_stream *s = (struct http2_stream *)c->arg[0];
    __u64 hd = 0;
    if (bpf_probe_read(&hd, sizeof hd, &s->http_data) != 0 || hd == 0)
        return LS_FALLTHROUGH;

    /* status_code != 0 distinguishes a RESPONSE from a request. Reached through
     * ci.http, an embedded-struct chain --- which resolves here because it is
     * hand-written C with named accessors, not a pointer hop. */
    struct http_data *p = (struct http_data *)hd;
    __u32 sc = 0;
    if (bpf_probe_read(&sc, sizeof sc, &p->ci.http.status_code) != 0)
        return LS_FALLTHROUGH;

    return sc != 0 ? LS_SAFE_RETURN : LS_FALLTHROUGH;
}
