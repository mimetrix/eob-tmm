/*
 * check_sr_gates.c — assert the safe-return two-gate rule holds in code.
 *
 * An earlier draft of shield_abi.h classified a hookable function as
 * enforce-capable by its RETURN TYPE alone, which let `void` through as the
 * trivial case. That is backwards: a void function is called entirely for its
 * side effects, so skipping its body discards all of them and the signature
 * tells you nothing about what they were. The review that caught it is recorded
 * in design-review-findings.md (F3).
 *
 * The fix put skippability first as gate 1, closed by default. This file exists
 * so that fix cannot silently regress: it fails the build if an unanalysed body
 * is ever treated as enforce-capable, whatever its return type.
 *
 * Run by `make check`. Exits nonzero on any violation.
 */
#include "shield_abi.h"
#include <stdio.h>

static int fails;

static void expect(const char *what, int got, int want)
{
    if (got != want) {
        printf("FAIL  %s: got %d, want %d\n", what, got, want);
        fails++;
    }
}

int main(void)
{
    /* Gate 1 closed by default: a void function whose body was never analysed
     * must NOT be enforce-capable. This is the case the retired model accepted,
     * and it is the whole reason the gate order matters. */
    struct shield_sr_policy void_unanalysed = { SKIP_UNANALYSED, SR_VOID, 0 };
    expect("void + unanalysed is refused", shield_sr_enforce_capable(&void_unanalysed), 0);

    /* Analysed and genuinely skippable: enforce-capable, and `void` is fine
     * HERE — because gate 1 carried the weight, not the return type. */
    struct shield_sr_policy void_analysed = { SKIP_YES, SR_VOID, 0 };
    expect("void + analysed is allowed", shield_sr_enforce_capable(&void_analysed), 1);

    /* Analysed and NOT skippable: a benign return value does not rescue it. A
     * lock held across the body, a refcount, an advanced flow state, a consumed
     * buffer, or an out-param the caller reads all land here. */
    struct shield_sr_policy effects_zero = { SKIP_NO, SR_ZERO, 0 };
    expect("side effects + benign zero is refused", shield_sr_enforce_capable(&effects_zero), 0);

    /* Gate 2 must still be reached: skippable but with no synthesizable return
     * is not enforce-capable either. */
    struct shield_sr_policy skippable_nokind = { SKIP_YES, SR_NONE, 0 };
    expect("skippable + no return kind is refused", shield_sr_enforce_capable(&skippable_nokind), 0);

    /* The default-initialized policy — what a generator emits when it has said
     * nothing — must be inert. Zero means observe-only, not enforce. */
    struct shield_sr_policy zeroed = { 0 };
    expect("all-zero policy is inert", shield_sr_enforce_capable(&zeroed), 0);

    if (fails) {
        printf("check_sr_gates: %d violation(s)\n", fails);
        return 1;
    }
    printf("ok    shield_abi.h  (safe-return two-gate rule: 5 cases, void-is-hardest enforced)\n");
    return 0;
}
