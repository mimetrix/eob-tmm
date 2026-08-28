/* SHIELD (DEMO / SYNTHESIZED CONDITION --- NOT FOR PRODUCTION).
 *
 * Identical in structure to dtls_txguard.bpf.c, with ONE change: the overflow
 * threshold is lowered far below the real SSL_SZ_RDATA (~16 KB) so that ORDINARY
 * DTLS traffic (mss ~1500, a normal handshake message) trips the predicate. Its
 * only purpose is to exercise the enforcement-evidence pipeline (SAFE_RETURN ->
 * ls_tp_emit_shield -> ring -> ls_drain) on live traffic without needing to drive
 * a genuinely oversized, stack-smashing DTLS message.
 *
 * ARM THIS IN MONITOR ONLY. In monitor the body still runs, so traffic is
 * unaffected; the shield merely SELECTS SAFE_RETURN and the host records the
 * evidence event. Arming this in ENFORCE would fail-close ordinary DTLS --- which
 * is the whole point of keeping it separate from the faithful shield, whose
 * threshold never fires on well-formed traffic.
 *
 * The faithful shield (dtls_txguard.bpf.c) is the real artifact. This one is
 * scaffolding for the "show me the evidence event" half of the demo, and the
 * drain record it produces is real; only the threshold is synthetic.
 */
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

static long (*bpf_probe_read)(void *, __u32, const void *) = (void *)4;

struct connflow { __u16 mss; }        __attribute__((preserve_access_index));
struct ssl_ctx  { struct connflow *cf; } __attribute__((preserve_access_index));

struct ls_ctx_generic { __u64 arg[5]; };

#define LS_SAFE_RETURN  1ull
#define LS_FALLTHROUGH  0ull

/* SYNTHETIC threshold --- far below the real ~16 KB record buffer, chosen so a
 * normal DTLS segment (mss ~1500, message a few hundred bytes) trips it. The
 * faithful shield uses SSL_SZ_RDATA (16384) here. */
#define LS_DEMO_MSS_THRESH   500u
#define LS_DEMO_SZ_THRESH    200ull

__attribute__((section("fentry/dtls_tx"), used))
__u64 dtls_txguard_demo(struct ls_ctx_generic *c)
{
    struct ssl_ctx  *sc = (struct ssl_ctx *)c->arg[0];
    __u64            sz = c->arg[3];
    struct connflow *cf = 0;
    __u16            mss = 0;

    if (sc == 0)
        return LS_FALLTHROUGH;
    if (bpf_probe_read(&cf, sizeof cf, &sc->cf) != 0 || cf == 0)
        return LS_FALLTHROUGH;
    if (bpf_probe_read(&mss, sizeof mss, &cf->mss) != 0)
        return LS_FALLTHROUGH;

    if ((__u32)mss > LS_DEMO_MSS_THRESH && sz > LS_DEMO_SZ_THRESH)
        return LS_SAFE_RETURN;             /* synthesized: trips on ordinary DTLS */

    return LS_FALLTHROUGH;
}
