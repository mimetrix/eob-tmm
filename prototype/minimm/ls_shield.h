/*
 * ls_shield.h — Live Shield ABI for the minimm prototype.
 *
 * This header is the contract between three parties:
 *   1. minimm (the bent-pipe relay / "mini-TMM") that exposes hook points,
 *   2. the reference shield compiled into minimm (Track 1), and
 *   3. the bpftime-loaded eBPF shield that attaches to the hook point (Track 2).
 *
 * It is the concrete, runnable analog of the design doc:
 *   - struct ls_ctx      <-> the per-build "arg_btf" a hook point exposes (design §5.3)
 *   - ls_verdict         <-> the enumerated filter outcomes owned by the host (§6.1)
 *   - struct ls_shared   <-> the shared "map": mode + evidence counters (§6, §7)
 *   - ls_request_eval_decision() <-> a named, versioned "filter" hook point (§5.3, §6.1)
 */
#ifndef LS_SHIELD_H
#define LS_SHIELD_H

#include <stdint.h>

#define LS_ABI_VERSION   2u
#define LS_SHM_NAME      "/minimm_ls"     /* POSIX shm backing the shared map  */
#define LS_HOOKPOINT_SYM "ls_request_eval_decision"

/* Flight recorder (observe-mode "black box", substrate §3.1). LS_FR_TRIGGER is
 * the high bit an observe program ORs into its return value to arm a dump; the
 * low byte stays the histogram sample. Must match the bytecode (ls_trace). */
#define LS_FR_DEPTH      8u               /* frames of run-up retained in the ring */
#define LS_FR_TRIGGER    0x100u           /* observe-program return flag: freeze+dump */

/* Enumerated outcomes the host code already knows how to take (design §6.1).
 * A shield may only *choose* among these; it cannot invent new control flow. */
enum ls_verdict {
    LS_PASS  = 0,   /* forward the frame to upstream (incl. into the parser) */
    LS_DROP  = 1,   /* drop this frame; keep the connection open             */
    LS_RESET = 2,   /* tear the connection down                              */
};

/* Operational modes (design §7). */
enum ls_mode {
    LS_DISABLE = 0, /* hook point is inert; always LS_PASS                   */
    LS_MONITOR = 1, /* detect + count, but do NOT act (falls through)        */
    LS_ENFORCE = 2, /* detect + act on the enumerated verdict                */
};

/* What the hook point exposes to a shield. In production this is described by
 * the per-build BTF in the hook-point map; here it is a fixed struct. */
struct ls_ctx {
    uint16_t opcode;          /* frame opcode (the field the synthetic CVE abuses) */
    uint16_t payload_len;     /* declared payload length from the frame header     */
    uint32_t avail_len;       /* bytes actually buffered for this frame            */
    uint32_t mode;            /* current enum ls_mode, supplied by the host so an  */
                              /* embedded-VM shield can branch on it (Track 2/uBPF)*/
    uint8_t  head[16];        /* first bytes of payload, for richer predicates     */
};

/* One captured frame summary in the flight recorder (substrate §3.1). */
struct ls_fr_entry {
    uint16_t opcode;
    uint16_t payload_len;
    uint32_t avail_len;
    uint8_t  head[8];                  /* first payload bytes, for context      */
};

/* The shared "map": mode + evidence. shm-backed so an out-of-band controller
 * (minimm ctl) and, in Track 2, the bpftime map bridge can read/write it. */
struct ls_shared {
    uint32_t abi_version;
    volatile int      mode;            /* enum ls_mode                          */
    volatile uint64_t hits;            /* predicate matches seen (evidence)     */
    volatile uint64_t enforced;        /* times a DROP/RESET was actually taken */
    volatile uint32_t last_opcode;     /* last offending opcode (diagnostics)   */
    volatile uint64_t trace[8];        /* observe-mode telemetry histogram      */
                                       /* (e.g. per-opcode counts from a        */
                                       /* tracepoint program; see LS_TRACE)     */

    /* Flight recorder (observe-mode, substrate §3.1): a ring of the most recent
     * frames seen at the hook, frozen + dumped when an observe program arms the
     * trigger (LS_FR_TRIGGER). shm-backed so the run-up SURVIVES a data-plane
     * crash for post-mortem (minimm ctl flightrec) — the core-dump's blind spot.
     * One ring here; per-CPU in production (design §11). */
    volatile uint32_t fr_head;         /* next write slot (mod LS_FR_DEPTH)     */
    volatile uint64_t fr_seen;         /* total frames recorded                 */
    volatile uint32_t fr_tripped;      /* 1 once a trigger froze the ring        */
    volatile uint64_t fr_trip_seq;     /* fr_seen at the triggering frame        */
    struct ls_fr_entry fr_ring[LS_FR_DEPTH];
};

/*
 * The hook point.  Designed-in, noinline, externally visible so its symbol is a
 * stable uprobe attach target (design §3.1 "instrument by design, do not inject").
 *
 *   attach_mode: filter   (return value selects an enumerated outcome)
 *   path_class:  cold      (only the malformed condition reaches the offending op)
 *
 * Track 1: minimm compiles a *reference shield* as this function's body.
 * Track 2: built with -DLS_HOOK_STUB, the body is an inert "return LS_PASS" and a
 *          bpftime uprobe on this symbol supplies the verdict instead.
 */
int ls_request_eval_decision(const struct ls_ctx *ctx);

#endif /* LS_SHIELD_H */
