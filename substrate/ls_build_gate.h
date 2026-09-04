/* ls_build_gate.h --- refuse a program signed for a different build.
 *
 * WHY THIS EXISTS. `struct shield_binding` has carried build_min, build_max and
 * expires_with since the ABI was written. They are covered by the signature ---
 * check_sig.c asserts a flipped bit in each IS detected --- and they are written
 * into every audit record. And until this file, nothing compared them to
 * anything. `grep -rn 'build_min' *.c *.h` outside shield_abi.h returned two
 * tests and the logger. See CONTESTED-PREMISES.md 15.
 *
 * That is the most expensive shape a gap can take: three separate trails (the
 * signed structure, a passing tamper test, the audit record) all read as
 * "enforced". SIGNING A FIELD IS NOT CHECKING IT, and a test that a field is
 * signed is not a test that it is honoured.
 *
 * WHY IT MATTERS MORE NOW. Removing the embedded `.BTF` (02-RESEARCH-PARAMETERS.md
 * P9) means field offsets get baked on the build box instead of resolved on-box
 * against the running binary's own type information. That deletes the property
 * which currently makes a stale offset structurally impossible. Baked offsets
 * plus an unenforced build range is silently-wrong reads with nothing able to
 * notice --- so this gate lands BEFORE that change, not after.
 *
 * THE ENCODING, DEFINED HERE BECAUSE IT WAS NEVER DEFINED ANYWHERE.
 * shield_abi.h called the field an "encoded build id" and no file said what the
 * encoding was. It is the FIRST FOUR BYTES of the GNU build id read as a
 * big-endian uint32 --- so build 269b5d25ad5d... is 0x269b5d25, which is the
 * convention already used by hand on the command line.
 *
 * AND WHY A "RANGE" IS ALMOST ALWAYS WRONG. A GNU build id is a SHA-1. A hash has
 * no ordering, so "builds 0x100 through 0x200" is not a statement about builds ---
 * it is an accident that admits roughly 2^-32 of all builds for no stated reason.
 * Only two forms mean anything, and everything else is refused rather than
 * silently accepted:
 *
 *   min == max                 this build, and no other
 *   0 .. 0xffffffff            ANY build --- the explicit wildcard
 *
 * The wildcard is accepted and logged LOUDLY. It has to be: sign_shield.py has
 * defaulted to it since it was written and bnk-build-programs.sh passes no range
 * at all, so every program ever signed by the pipeline carries it. Refusing it
 * would brick every existing artifact to prove a point. It is not an attacker
 * escape --- the range is inside the signature, so only our own key can assert
 * it --- it is us vouching too broadly, which is a pipeline fix (pass the range)
 * rather than a loader fix.
 *
 * expires_with IS DELIBERATELY NOT CHECKED HERE. Its semantics were never
 * defined either, and unlike build_min/build_max there is no reading that is
 * obviously right: "expires with build X" cannot be evaluated on a box that does
 * not know which build superseded X, and a uint32 epoch would be a different
 * field. Inventing a meaning and then enforcing it is worse than a documented
 * gap, so it stays a gap, logged, with the decision pre-registered in P9.
 *
 * Header-only and free of every TMM dependency on purpose: the decision is a pure
 * function of three integers and a string, so check_build_gate.c can assert every
 * branch of it off-TMM without a socket, a thread or a binary.
 */
#ifndef LS_BUILD_GATE_H
#define LS_BUILD_GATE_H

#include <stdint.h>

enum ls_build_verdict {
    LS_BUILD_OK = 0,       /* min == max and it matches the running build       */
    LS_BUILD_WILDCARD,     /* 0..0xffffffff --- accepted, must be logged loudly */
    LS_BUILD_MISMATCH,     /* signed for exactly one build, and not this one    */
    LS_BUILD_BAD_RANGE,    /* a range over a hash: meaningless, so refused      */
    LS_BUILD_NO_ID         /* the running build id is unreadable --- fail closed */
};

#define LS_BUILD_WILDCARD_MIN 0x00000000u
#define LS_BUILD_WILDCARD_MAX 0xffffffffu

static inline const char *
ls_build_strerror(enum ls_build_verdict v)
{
    switch (v) {
    case LS_BUILD_OK:        return "signed for this build";
    case LS_BUILD_WILDCARD:  return "signed for ANY build";
    case LS_BUILD_MISMATCH:  return "signed for a different build";
    case LS_BUILD_BAD_RANGE: return "build range spans a hash and cannot be honoured";
    case LS_BUILD_NO_ID:     return "this binary's build id is unreadable";
    }
    return "unknown";
}

/* First four bytes of a lowercase-hex GNU build id, big-endian.
 * Returns 0 on any malformed input and sets *ok = 0 --- a build id shorter than
 * 8 hex digits, or carrying a non-hex character, is not a build id, and guessing
 * at one is how a gate ends up admitting whatever it could not parse. */
static inline uint32_t
ls_build_prefix(const char *hex, int *ok)
{
    uint32_t v = 0;
    if (ok) *ok = 0;
    if (hex == 0)
        return 0;
    for (int i = 0; i < 8; i++) {
        char c = hex[i];
        uint32_t d;
        if      (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else return 0;                       /* short or non-hex: refuse */
        v = (v << 4) | d;
    }
    if (ok) *ok = 1;
    return v;
}

/* THE DECISION. `running_hex` is this binary's build id as hex (ls_audit_build_id()).
 * On a non-NULL `running_out` the parsed prefix is stored for logging, whatever the
 * verdict --- a refusal that cannot say which build it is running is hard to act on. */
static inline enum ls_build_verdict
ls_build_gate(const char *running_hex, uint32_t bmin, uint32_t bmax,
              uint32_t *running_out)
{
    int ok = 0;
    uint32_t running = ls_build_prefix(running_hex, &ok);
    if (running_out) *running_out = running;

    /* The wildcard is decided BEFORE the id is required. A program vouched for on
     * any build does not become invalid because this binary's note is unreadable,
     * and ordering it the other way would have made the gate's arrival break loads
     * on any binary whose build id we cannot parse. */
    if (bmin == LS_BUILD_WILDCARD_MIN && bmax == LS_BUILD_WILDCARD_MAX)
        return LS_BUILD_WILDCARD;

    if (!ok)
        return LS_BUILD_NO_ID;               /* fail closed once a range is asserted */
    if (bmin != bmax)
        return LS_BUILD_BAD_RANGE;
    return (running == bmin) ? LS_BUILD_OK : LS_BUILD_MISMATCH;
}

#endif /* LS_BUILD_GATE_H */
