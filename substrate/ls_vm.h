/*
 * ls_vm.h --- the embedded eBPF VM, as TMM would see it.
 *
 * This is the smallest interface that makes "TMM has its own BPF VM" a true
 * statement: a VM instance owned by TMM, created at startup, holding verified
 * programs, callable from a TMM code path, with its result acted on.
 *
 * Four calls. Everything else in development-scope.md --- the trampoline, pad
 * rewriting, the safe point, the signing chain --- exists to hook functions
 * NOBODY PLANNED FOR. None of it is needed to embed the VM itself, which is why
 * this is the first increment rather than the last.
 *
 * Shape follows TMM's, and the reasons matter:
 *
 *   - ONE VM PER TMM INSTANCE, never shared. TMM is core-pinned and
 *     run-to-completion, so a per-instance VM needs no lock on the call path.
 *     A shared VM would need one, and a lock in the poll loop is the thing this
 *     design cannot afford.
 *   - INTERPRETER, not the native-code path, for the first cut. uBPF's
 *     instruction limit "has no effect on JIT'd programs" (ubpf.h) but does work
 *     in the interpreter, and the native path's prologue opens a 4KB frame with
 *     no guard-page probe at arbitrary call depth (findings O6, O7). Switching
 *     later is one call, once those are addressed.
 *   - THE CTX IS A COPY. PREVAIL cannot express a read-only region, so a verified
 *     program can write every byte of what it is handed (finding O1). Handing it
 *     a live view of TMM state would make the safety mechanism deliver a
 *     state-injection primitive. The caller fills a per-instance scratch struct.
 *
 * Status: candidate artifact. It compiles against the real uBPF headers. It is
 * not wired into TMM here --- see ls_vm.c for exactly which lines would be the
 * TMM-side change.
 */

#ifndef LS_VM_H
#define LS_VM_H

#include <stdbool.h>
#include <stddef.h>   /* size_t --- this header must stand alone */
#include <stdint.h>

/* Outcomes the host owns. The program SELECTS one; the host APPLIES it. In
 * observe mode the host counts the selection and applies nothing --- observe is
 * not a seventh outcome (substrate §2). */
enum ls_verdict {
    LS_FALLTHROUGH = 0,   /* run the original function body                */
    LS_SAFE_RETURN = 1,   /* skip the body, return the declared safe value */
};

enum ls_mode {
    LS_MODE_DISABLE = 0,
    LS_MODE_MONITOR = 1,  /* evaluate and count; do not apply */
    LS_MODE_ENFORCE = 2,
};

/* The last few ctx values the hook was called with.
 *
 * Move-4 instrument: when the hook starts firing, `fired > 0` with
 * `safe_returns == 0` is ambiguous --- the shield may be wrong, or the CVE
 * condition may simply never have arrived. Without a sample there is no way to
 * tell those apart, and they call for opposite responses.
 *
 * Deliberately tiny and fixed: 8 entries of 32 bytes, in the slot, overwritten
 * oldest-first. This is development-scope.md item 14's ring at a scale that
 * needs no allocator, no drain agent and no backpressure policy --- the real one
 * is per-core shared memory with a consumer ABI. Sized to answer one question,
 * not to be that. */
#define LS_CTX_SAMPLES 8
#define LS_CTX_SAMPLE_BYTES 32

struct ls_ctx_sample {
    uint64_t seq;                              /* which invocation this was  */
    uint32_t len;                              /* the ctx's real length      */
    uint32_t verdict;
    uint8_t  bytes[LS_CTX_SAMPLE_BYTES];       /* truncated, deliberately    */
};

/* One armed program. TMM holds a small fixed array of these per instance ---
 * fixed because allocating on the call path is not acceptable. */

struct ls_slot {
    void        *vm;        /* struct ubpf_vm *, opaque here          */
    void        *jit_fn;    /* ubpf_jit_fn when JIT'd; NULL = interpret.
                             * Held separately because ubpf_exec never
                             * dispatches to compiled code --- the pointer IS
                             * the only route to it. */
    enum ls_mode mode;
    bool         armed;
    uint64_t     fired;         /* per-instance; a box-wide sum is wrong */
    uint64_t     safe_returns;
    uint64_t     errors;        /* exec faults: fuel exhausted, bounds  */
    uint64_t     cycles;        /* only when timing is enabled          */
    uint64_t     cycles_max;    /* the tail is what bounds a hot hook   */
    uint64_t     cycles_min;    /* the floor: least preemption-polluted */
    uint32_t     gen;           /* bumped per reload. Counters above are
                                 * per SLOT and SURVIVE a program swap ---
                                 * on 2026-08-17 a safe_returns=246 left by
                                 * one program was twice read as evidence
                                 * about the next. `gen` lets a reader tell
                                 * residue from result. */
    struct ls_ctx_sample samples[LS_CTX_SAMPLES];
    uint32_t     sample_next;
};

/* A snapshot of one slot, for whatever eventually reports these. Copied rather
 * than returning a pointer, because the caller must not be able to reach into
 * live VM state. The permanent home for these numbers is `tmstat`, TMM's own
 * statistics mechanism, which is already linked into the runtime image ---
 * see development-scope.md item 14. Until then, logging. */
struct ls_stats {
    bool     armed;
    int      mode;
    uint64_t fired;
    uint64_t safe_returns;
    uint32_t gen;            /* increments per reload --- see ls_vm_stats */
    uint64_t errors;
    uint64_t cycles;
    uint64_t cycles_max;
    uint64_t cycles_min;
};

/* The form TMM actually calls. Applies the environment overrides --- program
 * source, section, function, mode --- over the compiled-in defaults, so the
 * call site never has to know they exist. Pass the built-in blob and its two
 * identities; LS_SHIELD_PATH replaces the blob, LS_SHIELD_SECTION and
 * LS_SHIELD_FUNCTION replace the names, LS_SHIELD_MODE replaces the mode.
 *
 * This is what makes a shield change a pod restart rather than a rebuild. */
int ls_vm_arm_configured(const void *blob, size_t blob_len,
                         const char *section, const char *function);

/* Off the data path. Returns false for an out-of-range slot. */
/* The single STT_FUNC symbol defined in `section` of `elf`, copied into out[outlen].
 * Returns its length, or 0 if none/ambiguous. Lets the loader take a program's entry
 * function FROM the object it verified, instead of assuming a fixed name. */
size_t ls_function_in_section(const void *elf, size_t elf_len, const char *section,
                              char *out, size_t outlen);

bool ls_vm_stats(int slot, struct ls_stats *out);

/* Copy out the recent ctx samples. Off the data path. Returns how many were
 * written, up to LS_CTX_SAMPLES. */
unsigned ls_vm_samples(int slot, struct ls_ctx_sample *out, unsigned max);

/* Benchmark an ARBITRARY program without arming it onto a hook --- move-3
 * instrument. Loading a program, benching it and discarding it is what turns
 * budget-pass calibration from one restart per data point into one message per
 * data point. Returns 0 on success and fills min/mean/max.
 *
 * QUOTE THE MIN. The mean is 2-3x it and swings run to run --- 194 to 538 for one program on
 * an idle box --- because a single rdtsc pair spanning a context switch dominates the total.
 * That is the same effect that makes the armed-hook counter mean unusable, and it is why the
 * max is reported: seeing 130,720 next to a min of 132 is what tells a reader the mean is
 * measuring the scheduler.
 *
 * `jitted_out` says WHICH EXECUTION PATH was measured, and it is not optional information.
 * This function used to time the interpreter unconditionally while every armed hook runs
 * jit_fn, so the figure described a path nothing uses. It now compiles when the configuration
 * does, falls back to the interpreter if the JIT fails, and reports which happened --- a
 * caller that ignores this can publish an interpreter number as a hook cost, which is the
 * mistake the flag exists to prevent. Pass NULL only if you genuinely do not care.
 *
 * IT IS STILL A FLOOR, not the cost of an armed hook. It measures program execution in a
 * tight loop with a warm cache and no contention. A live hook additionally pays the
 * trampoline's register save and restore, the call and return, and cache effects from real
 * traffic. */
int ls_vm_bench_program(const void *elf, size_t elf_len,
                        const char *section, const char *function,
                        uint32_t iters,
                        uint64_t *min_out, uint64_t *mean_out, uint64_t *max_out,
                        int *jitted_out);

/* Whether signature enforcement is on --- see ls_vm_config.c for why the opt-out is a word
 * rather than a boolean. Exported so the loader does not become a second reader of the
 * environment; the one thing two config readers must never disagree about is whether a
 * security gate is armed. */
int ls_vm_sig_enforce(void);

/* Log the current counters for every armed slot. Called at fini, every
 * LS_VM_REPORT_EVERY invocations, and on demand. */
void ls_vm_report(void);

/* Create this instance's VM state. Called once per TMM instance at startup,
 * off the data path. Returns false and leaves nothing armed on any failure ---
 * a TMM that cannot bring up the VM must run exactly as it does today. */
bool ls_vm_init(void);

/* Load a VERIFIED, SIGNED program object into a slot and arm it. Off the data
 * path (admission time). Signature checking happens BEFORE this.
 *
 * BOTH names are required, and that is not redundancy --- the verifier and the
 * runtime identify a program differently:
 *
 *   PREVAIL  selects by ELF SECTION name   ("fentry/<hook>")
 *   uBPF     selects by FUNCTION SYMBOL    ("shield")   [ubpf_loader.c:271,
 *            despite its header calling the parameter `main_section_name`]
 *
 * So "PREVAIL verified this object" and "uBPF is about to run this program" are
 * statements about two different identities, and in an object carrying several
 * functions they can denote different code. This function refuses unless the
 * named symbol actually lives in the named section --- see finding O14. Passing
 * one name and hoping is how a verified-but-not-the-verified-one program loads.
 *
 * Returns the slot index, or -1. */
int ls_vm_arm(const void *elf, size_t elf_len,
              const char *section, const char *function, enum ls_mode m);

/* THE CALL PATH. Everything above is setup; this is the part that runs per
 * invocation and the only part whose cost is in the poll loop.
 *
 * ctx points at the caller's scratch copy of the fields the program needs.
 * Returns the verdict the host must apply, or LS_FALLTHROUGH on any error ---
 * fail-open is correct HERE and only here: a shield that cannot run must not
 * take TMM down with it. Admission fails closed; invocation fails open. */
enum ls_verdict ls_vm_call(int slot, void *ctx, size_t ctx_len);

/* Runtime load path (ls_vm_load.c). Started only if LS_LOAD_SOCKET is set.
 * VERIFIES EVERY PROGRAM'S SIGNATURE (ls_sig.c) and NOTHING ABOUT ITS SENDER: the
 * socket has no peer authentication, so the env gate and the 0600 mode are what
 * limit who may ask. Off by default for that reason --- which is a different reason
 * from the one this comment carried until 2026-08-20. */
void ls_vm_loader_start(void);

int  ls_vm_reload(int slot, const void *elf, size_t elf_len,
                  const char *section, const char *function, enum ls_mode m);
void ls_vm_set_mode(int slot, enum ls_mode m);

void ls_vm_fini(void);

#endif /* LS_VM_H */
