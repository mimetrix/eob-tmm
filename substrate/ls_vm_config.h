/*
 * ls_vm_config.h --- everything we might want to vary, made variable.
 *
 * Rationale, stated because it drove the design: on this setup a rebuild is
 * ~12 minutes of compile plus ~4 of save/copy/load, while an environment change
 * is a pod restart of about ten seconds. So the question for each knob is not
 * "is this elegant" but "if we get this wrong, or want to try the other value,
 * does that cost 20 minutes or 10 seconds."
 *
 * Everything here is read ONCE at init, off the data path. Nothing in this file
 * is consulted per invocation --- the per-call path reads only the slot.
 *
 * The list is derived from the questions already queued against this work:
 *
 *   "did the shield arm?"              -> LS_VM_VERBOSE, and a success line
 *   "has it ever fired?"               -> counters + LS_VM_REPORT_EVERY
 *   "what does one invocation cost?"   -> LS_VM_BENCH, LS_VM_TIMING
 *   "is the hook even reached here?"   -> first-invocation log
 *   "try monitor instead of enforce"   -> LS_SHIELD_MODE
 *   "try a different program"          -> LS_SHIELD_PATH   (this is rung 2)
 *   "is the JIT faster, and by how much?" -> LS_VM_JIT
 *   "does fuel change anything?"       -> LS_VM_FUEL
 *   "which build is actually running?" -> a build stamp at arm time
 *
 * Every one of those would otherwise have been a separate build.
 */

#ifndef LS_VM_CONFIG_H
#define LS_VM_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

struct ls_vm_config {
    bool     enable;        /* LS_SHIELD_ENABLE=0 disables everything, so a bad
                             * shield can be turned off without a rebuild and
                             * without reverting the integration */
    int      mode;          /* LS_SHIELD_MODE = disable|monitor|enforce        */
    const char *path;       /* LS_SHIELD_PATH: load the program from a FILE
                             * instead of the compiled-in blob. This is what
                             * makes changing a shield a restart rather than a
                             * rebuild --- rung 2 of three. NULL = use the blob */
    const char *section;    /* LS_SHIELD_SECTION --- what PREVAIL proved        */
    const char *function;   /* LS_SHIELD_FUNCTION --- what uBPF runs (O14)      */
    uint32_t fuel;          /* LS_VM_FUEL, 0 = uBPF default. Interpreter only:
                             * documented as having no effect once JIT'd (O6)  */
    bool     jit;           /* LS_VM_JIT=1 --- native code instead of the
                             * interpreter. Off by default: the JIT drops the
                             * instruction limit (O6) and its prologue opens a
                             * 4KB frame with no guard-page probe (O7). Present
                             * so the cost difference can be MEASURED without a
                             * rebuild, not because it is safe to switch on.    */
    uint32_t bench;         /* LS_VM_BENCH=N --- at init, run the program N times
                             * over a fixed ctx and report cycle statistics.
                             * Decouples the cost question from getting live
                             * traffic through one specific vulnerable path,
                             * which otherwise needs a listener configured with
                             * a protocol-transfer log profile.                 */
    bool     timing;        /* LS_VM_TIMING=1 --- accumulate cycles on the REAL
                             * call path. Default off, so the measured path and
                             * the shipped path are the same unless asked.      */
    uint32_t report_every;  /* LS_VM_REPORT_EVERY=N --- log counters every N
                             * invocations. 0 = only at fini.                   */
    bool     verbose;       /* LS_VM_VERBOSE=1 --- log arm success, the build
                             * stamp, and the first invocation. Without this the
                             * only observable state is failure, which is
                             * backwards for a demonstration.                   */
};

/* Read once, at init. Never called on the data path. */
void ls_vm_config_load(struct ls_vm_config *c);

#endif /* LS_VM_CONFIG_H */
