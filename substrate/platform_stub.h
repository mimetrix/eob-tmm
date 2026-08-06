/* platform_stub.h — the gaps that stop ../development-scope-code.md's skeletons
 * from being readable by a compiler. Nothing more than the gaps.
 *
 * WHY THIS EXISTS
 * ---------------
 * That document carries a candidate skeleton per development-scope item. They
 * were prose in fenced blocks: syntactically plausible C that no compiler had
 * ever read. That is a weaker artifact than it looks, and this proposal has
 * already shipped a defect of exactly that class — the JIT function-pointer
 * typedef was written as uBPF's 2-argument BasicJitMode form while the design
 * requires the 4-argument extended form with a per-core stack. A human reviewer
 * caught it; a compiler would have caught it for nothing.
 *
 * SCOPE — deliberately minimal
 * ----------------------------
 * The skeletons already declare most of their own platform surface with
 * `extern`, and shield_abi.h declares the rest (sig_verify, hook_map_lookup,
 * trampoline_arm/disarm, shield_msg_handle). This header must NOT restate any of
 * those: a second declaration that disagreed would be a defect this file
 * introduced rather than one it found. So all that lives here is what is
 * genuinely missing — two control-plane types, one bound, and the handful of
 * helpers no block declares.
 *
 *   WHAT A PASS MEANS   the skeletons agree with shield_abi.h and with each
 *                       other on types, struct fields, function arity and
 *                       signatures, enum members and control flow.
 *
 *   WHAT IT DOES NOT    that any of this runs. Nothing here is linked, and
 *                       nothing here is a proposal about TMM's real internal
 *                       API — these are the shapes the skeletons assume, made
 *                       explicit so the assumption is reviewable.
 */
#ifndef PLATFORM_STUB_H
#define PLATFORM_STUB_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shield_abi.h"

/* ---- one bound ----------------------------------------------------------- */

#ifndef SHIELD_MAX_CORES
#define SHIELD_MAX_CORES 64u    /* TODO(f5): the TMM instance count is a platform
                                 * fact, not a constant. A fixed array here is a
                                 * sketch convenience, and a real loader sizes
                                 * this from tmm_instance_count(). */
#endif

/* ---- two control-plane types ---------------------------------------------
 * Not in shield_abi.h on purpose: neither crosses the wire, so neither has a
 * layout for a _Static_assert to pin. They exist only between the loader daemon
 * and the operator front-end (items 10 and 11).
 */

/* One TMM instance's answer to a fanned-out op. */
struct shield_reply {
    int32_t  rc;             /* SHIELD_OK, or a SHIELD_ERR_*                   */
    uint8_t  mode;           /* enum shield_mode, as that instance now sees it */
    uint64_t fired;          /* this instance's counter, summed by the caller   */
};

/* What `status` renders. `total` is the sum over instances; `cores` records how
 * many answered, because a total over an unknown denominator is not a number
 * anyone can act on — a partial fanout has to be visible as partial. */
struct shield_status {
    int      cores;                      /* instances that answered            */
    uint64_t total;                      /* summed fire count across them      */
    uint8_t  mode;                       /* the mode they agree on             */
    uint64_t fired[SHIELD_MAX_CORES];    /* and kept PER INSTANCE, not only
                                          * summed: an even spread and a single
                                          * hot instance total the same, and
                                          * only one of them is a shield doing
                                          * its job. CMP/DAG decides which
                                          * instance sees a flow, so the
                                          * distribution is the signal. */
};

/* ---- helpers no block declares for itself -------------------------------- */

/* Address of the trampoline entry serving this slot. Arch-specific in reality;
 * required here only to type-check as a code address. */
void *tramp_entry_for(struct hook_slot *slot);

/* Refill a patched entry's pad with architecture-correct no-ops. */
void restore_nops(void *entry, uint32_t pad_len);

/* Constant-time compare. Plain memcmp leaks a prefix-match length through
 * timing, which is why the skeletons call this instead. */
int ct_equal(const void *a, const void *b, size_t len);

/* Per-hook monotonic replay guard: non-zero if `epoch` strictly advances. */
int epoch_advance(const char *hook, uint32_t epoch);

/* Monotonic timestamp, and the TMOS identity behind an op, for the audit trail. */
uint64_t tmm_now_ns(void);
void     control_plane_actor(char *out, size_t len);
void     tmm_audit_write(const void *rec, size_t len);

/* Rendering. */
const char *op_name(uint32_t op);
const char *shield_strerror(int rc);

/* A REVOKE is pre-issued alongside the LOAD it unwinds, so the kill switch does
 * not depend on the signing service being reachable when it is used. */
struct shield_msg *revoke_msg_for(const struct shield_msg *load, size_t *len);
struct shield_msg *signed_status_msg_for(const char *hook, size_t *len);

/* encode_jump is deliberately NOT declared here: item 2's block declares it
 * `static` itself, and a non-static declaration in this header would conflict —
 * a defect this file introduced rather than one it found. */

int  tmm_config_send(int inst, const void *msg, size_t len,
                     void *reply, size_t reply_len);

/* Logging. Macros rather than functions so the format strings in the skeletons
 * are still parsed for arity by -Wformat when a real logger is substituted. */
#define log_err(...)  ((void)0)
#define log_warn(...) ((void)0)
#define log_info(...) ((void)0)

#endif /* PLATFORM_STUB_H */
