/* ls_tp_shield.h --- tmm:shield:safe_return, the enforcement-evidence record.
 *
 * WHY THIS EXISTS. A counter that increments (safe_returns) answers "how many"
 * and nothing else. When a shield selects SAFE_RETURN on live traffic --- the
 * moment it prevents a crash --- a security reviewer needs a pushed record with
 * the evidence: which hook, which program, when, and the context the shield saw.
 * That is what this schema carries, and it rides the SAME per-core ring and drain
 * as the designed-in tracepoints (ls_tp_ring.h / ls_drain.c). The event is the
 * proof; the counter is only the tally.
 *
 * HOST-EMITTED, not program-emitted. The host publishes it when it applies (or,
 * in monitor mode, WOULD apply) a SAFE_RETURN --- so an armed shield cannot
 * suppress its own audit trail by choosing not to emit. The bytes are the host's
 * ctx copy, so the schema is ours to vouch for (unlike LS_TP_SCHEMA_PROG).
 *
 * FIXED-WIDTH, NO POINTERS, ABI-STABLE. `unsigned int` is 32 bits and
 * `unsigned long long` 64 on the TMM target and in the drain (LP64), so the
 * producer (ls_tp_emit.c) and consumer (ls_drain.c) agree byte-for-byte. The
 * drain keeps its own mirror + a _Static_assert on this size, as for every schema.
 */
#ifndef LS_TP_SHIELD_H
#define LS_TP_SHIELD_H

/* The evidence payload. The ring HEADER (struct ls_rec) already carries seq,
 * slot, ts_ns, hook_id and schema_id, so this holds only what is shield-specific.
 *
 * arg[] is the generic five-register context the program was handed --- the SAME
 * bytes it read its verdict from. For the dtls_tx shield that means arg[0] = the
 * ssl_ctx pointer and arg[3] = sz, the message size: an oversized sz beside a
 * SAFE_RETURN is the observable signature of the fragment that would have
 * overflowed. mss itself is behind a pointer the shield dereferenced and is not
 * in the flat ctx; sz is, and sz is the attacker-controlled quantity. */
struct ls_tp_shield_ev {
    unsigned int       mode;      /* enum ls_mode: 1 monitor (WOULD block), 2 enforce (blocked) */
    unsigned int       gen;       /* program generation that selected SAFE_RETURN */
    unsigned int       verdict;   /* the program's raw return (LS_SAFE_RETURN = 1) */
    unsigned int       ctx_len;   /* real ctx length the shield saw (bytes)        */
    unsigned long long arg[5];    /* the ctx: arg[0]=arg0 .. arg[3]=sz .. arg[4]    */
};

#endif /* LS_TP_SHIELD_H */
