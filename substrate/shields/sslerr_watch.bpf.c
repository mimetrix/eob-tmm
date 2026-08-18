/* tmm:ssl:err --- observe every TLS failure decision, and count them by alert.
 *
 * WHAT THIS ANSWERS THAT NOTHING ELSE DOES. An iRule sees CLIENTSSL_HANDSHAKE fail. It
 * does not see why, and the alert on the wire barely narrows it: 210 of TMM's 475
 * ssl_err sites pass SSL_A_INTERNAL_ERROR and 110 pass SSL_A_ILLEGAL_PARAM. The
 * diagnosis is the SITE (__func__ plus __LINE__) and the MESSAGE, and that pair exists
 * only inside TMM.
 *
 * ALWAYS FALLS THROUGH. This is a tracepoint, not a shield: it must never alter a TLS
 * failure path. The guarantee is structural rather than a promise --- there is no
 * `return LS_SAFE_RETURN` anywhere below, so the program cannot select one. Arm it in
 * MONITOR as well and the host applies nothing regardless.
 *
 * THE MAP IS PER THREAD, keyed by ALERT CODE. Keying by site would be more precise and
 * is not possible here: there is no map-iteration helper, so a consumer cannot enumerate
 * what a site-keyed map accumulated. The alert space is small and known, so a fixed key
 * per alert is readable by a later periodic reader. The per-record stream in the ring
 * carries the site; the map carries the shape of the traffic.
 *
 * WHY THE MAP IS NAMED sslerr_by_alert AND NOT `rate`. Map identity is the SYMBOL NAME
 * as of 2026-08-18. A map called `rate` here would SHARE storage with rate_watch's map
 * of the same shape, and the two programs would silently add into each other's counts.
 * Before that change identity was the shape alone, so the collision was guaranteed and
 * invisible.
 */
#include "ls_ctx_sslerr_bpf.h"

typedef unsigned int  __u32;
typedef unsigned long long __u64;

struct bpf_map_def {
    __u32 type, key_size, value_size, max_entries, map_flags;
};
#define BPF_MAP_TYPE_HASH 1

struct bpf_map_def sslerr_by_alert __attribute__((section("maps"), used)) = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 64,
};

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;

__attribute__((section("fentry/ssl__err"), used))
__u64
shield(struct ls_ctx_sslerr *c)
{
    __u32 key = c->alert;
    __u64 *n = bpf_map_lookup_elem(&sslerr_by_alert, &key);
    __u64 one = 1;

    if (n)
        one = *n + 1;
    bpf_map_update_elem(&sslerr_by_alert, &key, &one, 0);

    /* WRITE BACK INTO THE CTX, which is what makes this more than a counter. The host
     * publishes the record AFTER the program runs (see ls_tp.h), so a consumer sees
     * what the program left. Marking the running count of this alert in a field the
     * record already has means the JSON line says "this is the 41st illegal_parameter
     * on this thread" without a second lookup anywhere downstream.
     *
     * cookie_hi is NOT reused for it --- overwriting the flow identity would destroy
     * the correlation with the reset record, which is the more valuable field. There is
     * no spare field at 96 bytes, so the count goes nowhere and the map holds it. Stated
     * rather than silently skipped: a future ctx with two spare bytes should carry it. */

    return LS_FALLTHROUGH;    /* a tracepoint never selects --- structurally */
}
