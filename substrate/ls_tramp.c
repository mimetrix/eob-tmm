/*
 * ls_tramp.c --- the C half of the patched-entry trampoline.
 *
 * The assembly in trampoline_x86_64.S is generic: it saves the ABI's argument
 * registers, calls this, and acts on the verdict. Everything PER-HOOK lives
 * here, in C, because the ctx layout is generated from the build's DWARF
 * (development-scope.md item 6) and changes whenever a hooked function's
 * signature does. Putting it in assembly would mean regenerating assembly per
 * hook, which is the cost this split exists to avoid.
 *
 * Status: candidate artifact. It compiles. Nothing calls it --- arming (item 2)
 * is what would write the jump that reaches the assembly that reaches this.
 */

#include "ls_vm.h"
#include "ls_arm.h"
#include "ls_slots.h"
#include "ls_ctx_parse.h"
#include "ls_ctx_alpn_abi.h"
#include "ls_ctx_rst.h"
#include "ls_ctx_h2abort.h"
#include "ls_ctx_sslerr.h"
#include "ls_flow_cookie.h"
#include "ls_ssl_cookie.h"
#include "ls_tp.h"

/* Slot numbers live in ls_slots.h, checked for collisions by the compiler. They
 * were here as a bare macro whose value (0, the shield slot) contradicted the
 * comment above it (7) --- so slot 0 got the parse ctx instead of the generic
 * register ctx. See ls_slots.h. */

#include <stdint.h>
#include <string.h>

/* What the assembly expects back. rax carries this; rdx carries the safe value
 * when it is 1. Kept as plain ints because the asm reads eax. */
#define LS_TRAMP_FALLTHROUGH 0
#define LS_TRAMP_SAFE_RETURN 1

/*
 * Called with the hooked function's first five integer arguments, exactly as
 * the ABI delivered them, before its prologue ran.
 *
 * The returned safe_value is what the hooked function's caller should see if we
 * skip the body; the assembly moves it to rax. What counts as safe is per-hook
 * and belongs to the safe-return policy table (item 7); a slot carries its own.
 *
 * Returns LS_TRAMP_SAFE_RETURN to skip the hooked function entirely.
 */
/*
 * Returned in rax:rdx by the System V ABI --- which is precisely the pair the
 * assembly reads. An earlier draft took a seventh `uint64_t *safe_out`
 * argument; the ABI puts a seventh argument on the STACK, while the call site
 * passes only six registers, so the callee would have dereferenced whatever
 * happened to be at that address. Returning the pair removes the mismatch by
 * construction rather than by both sides remembering the same convention.
 */
/* struct ls_tramp_result lives in ls_arm.h */

struct ls_tramp_result
ls_tramp_dispatch(int slot, const struct ls_regs *regs)
{
    struct ls_tramp_result r = { LS_TRAMP_FALLTHROUGH, 0 };

    /*
     * ALL SIX arguments, via a pointer to the block the trampoline already saved
     * (Phase 3). The named accessors in ls_arm.h exist because the block is in
     * STACK order, which is the reverse of ABI order --- indexing it by argument
     * position would silently swap arguments rather than fail.
     *
     * regs is NULL only if something other than the trampoline called this. Guard
     * rather than trust: a fall-through is always a safe answer.
     */
    uint64_t a0, a1, a2, a3, a4, a5;

    if (regs == 0)
        return r;

    a0 = LS_ARG0(regs);
    a1 = LS_ARG1(regs);
    a2 = LS_ARG2(regs);
    a3 = LS_ARG3(regs);
    a4 = LS_ARG4(regs);
    a5 = LS_ARG5(regs);
    /*
     * The ctx is a per-invocation stack copy, never a view onto the argument
     * registers or onto TMM state. PREVAIL cannot express a read-only region,
     * so a verified program can write every byte of what it is handed
     * (finding O1); handing it the live frame would make the safety mechanism
     * an argument-injection primitive.
     *
     * Sized and shaped per hook in the real thing --- generated alongside the
     * hook map. This generic five-slot form is what an untyped `tracing`
     * program sees, and it is deliberately flat: no pointers out.
     */
    struct {
        uint64_t arg[5];
    } ctx;

    ctx.arg[0] = a0;
    ctx.arg[1] = a1;
    ctx.arg[2] = a2;
    ctx.arg[3] = a3;
    ctx.arg[4] = a4;

    /* Per-hook ctx. The generic five-register form above is what an untyped
     * program sees and is useless for most hooks, because nearly every TMM
     * function takes pointers and a verified program cannot chase one. So the
     * dereferencing happens HERE, in the host, and the program receives flat
     * scalars --- which is the canonical case PREVAIL already proves.
     *
     * Slot-selected rather than table-driven: one generated ctx, deliberately,
     * until this shape is proven end to end. LS_CTX_SLOT_PARSE is the hook
     * survey found to be the only one on this traffic's path
     * (http_parse_client_headers, 1:1 with requests). */
    if (slot == LS_CTX_SLOT_PARSE) {
        struct ls_ctx_parse pc;
        ls_ctx_build_parse(&pc, (const void *)a0, (const void *)a2);
        if (ls_vm_call(slot, &pc, sizeof pc) != LS_SAFE_RETURN)
            return r;
    } else if (slot == LS_CTX_SLOT_RST     || slot == LS_CTX_SLOT_RST_VA ||
               slot == LS_CTX_SLOT_RST_PRE || slot == LS_CTX_SLOT_RST_PRE_VA) {
        /* rst_why(uf, file, lineno, err, reason, rst_cause) --- every field is a
         * direct argument, so no derivation and nothing to snapshot before it is
         * overwritten.
         *
         * a5 IS rst_cause, and it arrives now. It was dropped until Phase 3 because
         * the trampoline forwarded five arguments; file:line identifies the site,
         * but at flow_table.c:2618 the cause is flow_reject_cause[flow_reject_code]
         * --- a runtime table lookup that no amount of reading the source recovers. */
        /* a0 is `uf`, the flow. It was forwarded and ignored until now. The cookie
         * comes from ls_flow_cookie.c because UFLOW_COOKIE() needs TMM's flow types
         * and this file is STDINC. A NULL uf yields 0, which is a legitimate answer:
         * flow_table.c rejects flows before one exists. */
        struct ls_ctx_rst rc;

        /* ALL THREE reset functions land here. RST_WHY* macros expand to three
         * different functions covering 1,116 call sites between them, and hooking
         * only rst_why saw 966 of them:
         *
         *   rst_why         (uf, file, lineno, err, reason, cause)
         *   rst_why_va      (uf, file, lineno, err, reason, cause, fmt, ...)
         *   rst_why_preserve(uf, file, lineno, err, cause)
         *
         * rst_why_va's first six arguments are IDENTICAL to rst_why's --- its varargs
         * start at the seventh, and this dispatcher only ever reads the first six ---
         * so it shares this builder verbatim. The header confirms the cause is a
         * static string even there; the varargs carry additional detail we do not
         * read, which is why nothing here has to understand them.
         *
         * rst_why_preserve has NO `reason`, so everything after `err` shifts down one:
         * the cause is a4 (r8), not a5 (r9). Reading a5 there would hand the record
         * whatever the caller happened to leave in r9 --- a plausible-looking pointer
         * dereferenced as a string, which is the worst shape of wrong. */
        /* TWO SHAPES, FOUR SLOTS. The preserve pair has no `reason`, so everything
         * after `err` shifts down one and the cause is a4 rather than a5. The other
         * pair takes the full six. Each function has its OWN slot so the record can
         * name which fired --- possible only since the trampoline became per-slot. */
        unsigned int hook;

        if (slot == LS_CTX_SLOT_RST_PRE || slot == LS_CTX_SLOT_RST_PRE_VA) {
            ls_ctx_rst_build(&rc, (const char *)a1, (unsigned int)a2,
                             (unsigned int)a3, 0u, (const char *)a4,
                             (unsigned long long)ls_uflow_cookie((void *)a0));
            hook = (slot == LS_CTX_SLOT_RST_PRE) ? LS_TP_HOOK_RST_PRE
                                                 : LS_TP_HOOK_RST_PRE_VA;
        } else {
            ls_ctx_rst_build(&rc, (const char *)a1, (unsigned int)a2,
                             (unsigned int)a3, (unsigned int)a4, (const char *)a5,
                             (unsigned long long)ls_uflow_cookie((void *)a0));
            hook = (slot == LS_CTX_SLOT_RST) ? LS_TP_HOOK_RST : LS_TP_HOOK_RST_VA;
        }
        /* ls_tp_dispatch, not ls_vm_call: it runs the program AND publishes the
         * record to the shared-memory ring, so an entry-armed hook produces a
         * stream rather than only counters. The ring is off unless LS_TP_RING
         * names a segment. */
        if (ls_tp_dispatch(slot, &rc, sizeof rc, hook) != LS_SAFE_RETURN)
            return r;
    } else if (slot == LS_CTX_SLOT_H2ABORT) {
        /* http2_stream_abort(stream, why, err) --- three direct arguments, nothing
         * derived, nothing to snapshot. The simplest hook in the set, and the only one
         * that passes all four uniqueness tests: its reason reaches no log, no iRule
         * event and no trace in a production build. */
        struct ls_ctx_h2abort hc;

        ls_ctx_h2abort_build(&hc, (unsigned long long)a0, (const char *)a1,
                             (unsigned int)a2);
        if (ls_tp_dispatch(slot, &hc, sizeof hc, LS_TP_HOOK_H2ABORT) != LS_SAFE_RETURN)
            return r;
    } else if (slot == LS_CTX_SLOT_SSLERR) {
        /* ssl__err(sc, alert, __func__, __LINE__, ...) --- the TLS twin of rst_why.
         *
         *   a0 sc     struct ssl_ctx *   -> the cookie, via the ssl-world crossing
         *   a1 alert  enum ssl_alert
         *   a2 func   __func__           NOT __FILE__, which ssl_err does not pass
         *   a3 line   __LINE__
         *   a4 msg    the FIRST VARARG
         *
         * The message is a vararg, so it lands in r8 --- within the six registers the
         * trampoline already forwards, which is the only reason this hook needs no asm
         * change. 462 of the 475 sites pass a plain literal, so for those the captured
         * string is the whole message; the 3 that pass a real format give us the format,
         * and ls_ctx_sslerr.h says so rather than implying otherwise.
         *
         * NO SNAPSHOT TIMING PROBLEM, unlike ALPN: every field is a direct argument read
         * before the function's body runs, so nothing is derived and nothing has been
         * overwritten by the time we look. The one derivation is the cookie, and a NULL
         * sc or NULL sc->cf yields 0 --- legitimate, since ssl__err fires on paths where
         * no connflow is attached yet. */
        struct ls_ctx_sslerr ec;

        ls_ctx_sslerr_build(&ec, (unsigned int)a1, (const char *)a2,
                            (unsigned int)a3, (const char *)a4,
                            (unsigned long long)ls_ssl_cookie((void *)a0));
        if (ls_tp_dispatch(slot, &ec, sizeof ec, LS_TP_HOOK_SSLERR) != LS_SAFE_RETURN)
            return r;
    } else if (slot == LS_CTX_SLOT_ALPN) {
        /* ssl_alpn_match(sc, skip_ext, skip_ext_len): the ALPN bytes are NOT an
         * argument --- the function derives them from `sc` in its first ten
         * lines. The builder repeats that derivation one step earlier, in the
         * ssl module's include world (ls_ctx_alpn.c), and hands back flat bytes.
         *
         * A zero return means there is no ALPN list to judge. Fall through
         * WITHOUT running the program: judging bytes that do not exist would
         * make the verdict noise rather than a finding. */
        unsigned char ac[LS_CTX_ALPN_SZ];
        if (ls_ctx_alpn_build_v(ac, (void *)a0) == 0)
            return r;
        if (ls_vm_call(slot, ac, sizeof ac) != LS_SAFE_RETURN)
            return r;
    } else if (ls_vm_call(slot, &ctx, sizeof ctx) != LS_SAFE_RETURN) {
        return r;
    }

    /*
     * TODO(f5): the safe value belongs to the slot, from the safe-return policy
     * table. Zero is right for a pointer-returning or BOOL-returning hook and
     * wrong for one whose caller treats 0 as success --- which is exactly why
     * item 7 exists and why v1 is restricted to trivial returns. Returning a
     * wrong "safe" value is worse than not shielding: it converts a crash into
     * silent misbehaviour.
     */
    r.verdict    = LS_TRAMP_SAFE_RETURN;
    r.safe_value = 0;
    return r;
}
