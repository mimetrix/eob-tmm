/* SHIELD (DEMO / evidence-pipeline exercise --- monitor-only).
 *
 * Purpose: fire the enforcement-evidence event (tmm:shield:safe_return) reliably on
 * live traffic, to demonstrate the event pipeline end to end. It attaches to
 * http_parse_client_headers --- the hook the surfaces already relocate against
 * cleanly and which fires exactly once per request --- reads one proven-relocating
 * field so the program carries a real CO-RE relocation (a zero-relocation program is
 * refused, rc=-3), and selects SAFE_RETURN every time.
 *
 * ARM IN MONITOR ONLY. In monitor the body still runs, so traffic is unaffected; the
 * host counts the SAFE_RETURN selection and emits the evidence record. Unconditional
 * SAFE_RETURN in ENFORCE would skip every header parse --- which is why the signed
 * binding's mode ceiling is monitor.
 *
 * This is scaffolding to SEE the evidence event, not a real shield: a real shield
 * returns SAFE_RETURN on a specific exploit precondition. The dtls_txguard shields do
 * that; their live arm is blocked on a relocator fix (a forward-declared connflow type
 * defeats the pointer-chase read of sc->cf->mss). The drain record here is real; only
 * the trip condition is unconditional.
 */
typedef unsigned char      __u8;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

/* The same minimal view the working surfaces use --- version_num relocates cleanly. */
struct http_parse_ctx { __u8 state; __u8 version_num; } __attribute__((preserve_access_index));

struct ls_ctx_generic { __u64 arg[5]; };

#define LS_SAFE_RETURN  1ull
#define LS_FALLTHROUGH  0ull

__attribute__((section("fentry/http_parse_client_headers"), used))
__u64 evidence_demo(struct ls_ctx_generic *c)
{
    struct http_parse_ctx *h = (struct http_parse_ctx *)c->arg[0];
    __u8 ver = 0;

    /* One real relocation so the program is not zero-relo (rc=-3). The value is not
     * used to decide --- this is the unconditional demo trip. */
    if (bpf_probe_read(&ver, sizeof ver, &h->version_num) != 0)
        return LS_FALLTHROUGH;

    return LS_SAFE_RETURN;      /* every request --> one evidence event (monitor) */
}
