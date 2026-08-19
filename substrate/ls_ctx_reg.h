/* ls_ctx_reg.h --- each ctx builder declares the function it serves. Nothing lists them.
 *
 * THE PROBLEM THIS SOLVES. A hook's ctx builder has to be found from the function that was
 * armed. Doing that with the slot number was wrong (ls_slots.h records the measurement:
 * an arbitrary function in slot 2 had its registers read as rst_why's arguments, including
 * a1 dereferenced as a string for up to 256 bytes). Doing it with a hand-written table of
 * names in one file is the same mistake relocated --- it drifts the moment someone adds a
 * builder and forgets the table, and nothing catches that.
 *
 * SO THE BUILDERS REGISTER THEMSELVES. Each builder's translation unit emits a pointer into
 * a dedicated section; the linker gathers them and defines __start_/__stop_ bounds. Adding a
 * builder is adding a file. Removing one removes its entry. There is no central list to be
 * out of date, and no slot number to be wrong.
 *
 * This is the mechanism TMM already uses for startup --- INIT_FUNC registers into a linker
 * set in local/sys/init.h, which is how urlcat, pem_lib and the substrate itself reach their
 * own initialisation without anything calling them. Same shape, different set.
 *
 * AN UNREGISTERED FUNCTION IS NOT AN ERROR. It gets the generic five-register context and no
 * dereference, which is precisely what a generated probe expects. That is why lookup returns
 * NULL rather than failing: "nobody wrote a typed builder for this" is the common case now,
 * not the exception.
 *
 * RESOLVED ONCE, AT ARM TIME. The slot stores the resolved pointer, so the data path is an
 * indirect call and not a search. A per-invocation string compare over the set would be a
 * measurable cost on a function that fires per request.
 *
 * IF THE LINKER DISCARDS THE SECTION every lookup returns NULL and every typed hook silently
 * degrades to the generic ctx --- safe, and silent, which is the dangerous combination this
 * repo keeps being bitten by. ls_ctx_reg.c therefore reports the count at startup and
 * substrate/check_ctx_reg.c fails the build if the linked count disagrees with the number of
 * LS_CTX_REGISTER uses in the sources.
 */
#ifndef LS_CTX_REG_H
#define LS_CTX_REG_H

/* The greatest number of bytes any builder may write. PREVAIL admits at most 96 bytes of
 * fentry ctx (measured, LIMITATIONS.md 1.3), so a builder that wants more is not describing
 * something a program can read. The bound is here rather than per-builder so the trampoline
 * can hold one stack buffer for all of them. */
#define LS_CTX_OUT_MAX 96u

/*
 * Build a record from the six saved argument registers.
 *
 * `args` is the saved register block --- args[0]..args[5] are rdi..r9 as the hooked function
 * received them. A builder reads only what its function's signature says is there; reading
 * further gets whatever the caller left in that register, which is how a plausible-looking
 * pointer gets dereferenced as a string.
 *
 * Returns bytes written, or 0 to FALL THROUGH WITHOUT RUNNING THE PROGRAM. Zero is a real
 * answer, not a failure: ls_ctx_alpn_build_v returns it when there is no ALPN list to judge,
 * and running a program over bytes that do not exist makes the verdict noise.
 */
typedef unsigned long (*ls_ctx_build_fn)(void *out, const unsigned long long *args);

struct ls_ctx_reg {
    const char      *hook;      /* the function name this builder serves, exactly       */
    ls_ctx_build_fn  build;
    unsigned long    size;      /* bytes `build` writes when it writes any              */
    unsigned int     hook_id;   /* LS_TP_HOOK_* --- what the published record claims to
                                 * be. From the builder, so a record's identity and its
                                 * layout are declared in the same place. */
};

/*
 * Register a builder. The name is derived from the symbol so two registrations in one file
 * cannot collide silently, and `used` keeps it through -O2 since nothing references it.
 *
 * The section name is a valid C identifier on purpose: that is the condition under which the
 * GNU linker defines __start_/__stop_ for it.
 */
#define LS_CTX_REGISTER(sym)                                                  \
    static const struct ls_ctx_reg *const ls_ctx_regptr_##sym                 \
        __attribute__((section("ls_ctx_regs"), used)) = &sym

extern const struct ls_ctx_reg *const __start_ls_ctx_regs[];
extern const struct ls_ctx_reg *const __stop_ls_ctx_regs[];

/* -> the builder for `hook`, or NULL for "no typed builder, use the register block".
 * Exact match only: "rst_why" and "rst_why_preserve" differ by a suffix and take different
 * builders, because the preserve form has no `reason` and its cause is in a4 rather than a5.
 * A prefix match would hand one function's registers to the other's builder. */
const struct ls_ctx_reg *ls_ctx_reg_lookup(const char *hook);

/* How many builders the linker actually gathered. Reported at startup; a build where this is
 * zero has lost the section and every typed hook has silently become generic. */
unsigned ls_ctx_reg_count(void);

/* Log the count and the registered hooks, once, from startup. Loud rather than fatal --- see
 * the comment on the definition for why a lost section degrades instead of refusing to run. */
void ls_ctx_reg_report(void);

/*
 * The builder a slot's program declared, or NULL for "generic, dereference nothing".
 *
 * Defined in ls_vm.c, which owns the slot table; declared here rather than in ls_vm.h so the
 * trampoline can reach it without pulling in struct ls_slot. NULL covers an out-of-range
 * slot, an unarmed slot and an unregistered hook, because all three mean the same thing to
 * the caller.
 */
const struct ls_ctx_reg *ls_vm_ctx_reg(int slot);

#endif /* LS_CTX_REG_H */
