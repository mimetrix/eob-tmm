/*
 * ls_vm.c --- the embedded eBPF VM. The whole of it.
 *
 * ~120 lines of real code against uBPF's real API. This is what makes the
 * sentence "TMM has its own BPF VM" true; everything else in the scope list is
 * about reaching functions nobody planned for.
 *
 * THE TMM-SIDE CHANGES, in full --- three places, and no more:
 *
 *   1. src/compile/Makefile   link the library
 *          CFLAGS  += -I$(TOPDIR)/.ubpf/vm/inc
 *          LDFLAGS += $(TOPDIR)/.ubpf/build/lib/libubpf.a
 *
 *   2. TMM instance startup, beside the other per-instance init:
 *          ls_vm_init();
 *
 *   3. A call site. One, to start with, at a place already known to fault:
 *
 *          static bool
 *          http_psm_profile_name_lookup(enum errdefs_key key, void *source,
 *                                       errdefs_append append_fn, void *dest)
 *          {
 *              struct http_psm_log_data *log_data = source;
 *              struct http_scb *scb = log_data->scb;
 *              struct connflow *cf = uflow_get_connflow(scb->uf);
 *              struct fw_log_profile_protocol_transfer *ptlp =
 *                  flow_get_listener(cf)->prot_transfer_log_profile;
 *
 *     +        struct ls_ctx_http_psm c = {                  // per-core scratch
 *     +            .ptlp      = (uint64_t)(uintptr_t)ptlp,
 *     +            .ptlp_name = ptlp ? (uint64_t)(uintptr_t)ptlp->name : 0,
 *     +            .name_len  = (ptlp && ptlp->name) ? (uint32_t)strlen(ptlp->name) : 0,
 *     +        };
 *     +        if (ls_vm_call(ls_ptlog_slot, &c, sizeof c) == LS_SAFE_RETURN)
 *     +            return false;                             // the declared safe value
 *
 *     and at init, passing BOTH identities (O14):
 *     +        ls_ptlog_slot = ls_vm_arm(blob, sizeof blob,
 *     +                                  "fentry/http_psm_profile_name_lookup",
 *     +                                  "shield", LS_MODE_ENFORCE);
 *
 *              const char *str = ptlp->name;
 *              return append_fn(str, strlen(str), dest);
 *          }
 *
 * That third block is the entire per-hook cost, and it is the DESIGNED-IN form:
 * a deliberate call site in source F5 owns. The trampoline and pad-rewriting
 * work exists to get this same effect at a function nobody edited --- a bigger
 * claim, and not this one.
 *
 * Note what the call site does NOT do: it does not consult the mode. The program
 * always selects the outcome its predicate implies and the host decides whether
 * to apply it, because gating mode inside the program would make a monitor-mode
 * hit indistinguishable from a miss.
 *
 * Status: candidate artifact. Compiles against the vendored uBPF headers.
 * Nothing in this repo instantiates it inside TMM.
 */

#include "ls_vm.h"
#include "ls_vm_config.h"
#include "vm_stack_policy.h"
#include "ls_map.h"
#include "ls_map_glue.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>   /* free() for uBPF's error strings */
#include <string.h>

#include "ubpf.h"

/* 12, matching the LS_TRAMP expansions in trampoline_x86_64.S. The two are compared
 * at arm time against the count that file publishes --- see ls_arm.c --- because a
 * C-side constant larger than the real table indexes past .rodata and arms a wild
 * address. Raised from 8 on 2026-08-18 for the ssl__err tracepoint plus headroom. */
#define LS_MAX_SLOTS 12

/*
 * Per-instance program stack, allocated once.
 *
 * ubpf_exec() declares `uint64_t stack[UBPF_EBPF_STACK_SIZE/8]` --- 4 KB --- as a
 * local, so every invocation pushes and touches a 4 KB frame at whatever depth
 * TMM's call graph happens to be at. That is the same hazard finding O7 raised
 * against the JIT prologue, present on the interpreter path as well, and it is
 * paid per call rather than once.
 *
 * ubpf_exec_ex() takes the stack from the caller, so we allocate it once per TMM
 * instance and hand the same one to every invocation. Safe here for the reason
 * the rest of this file is lock-free: one VM per instance, run-to-completion, so
 * two invocations never overlap on a core. It would NOT be safe if a hook could
 * be re-entered --- a shield that somehow triggered the hooked path again would
 * corrupt its own stack, which is why re-entrancy is on the trampoline's
 * requirement list (scope item 1) rather than assumed away.
 */
/* Defined below ls_vm_call, which it uses; declared here because ls_vm_arm
 * invokes it. */
static void ls_vm_selftest(int slot, unsigned level);

static uint8_t *g_prog_stack;
#define LS_PROG_STACK_SIZE 4096

/* Per TMM instance. Not shared, not locked --- see the header. `static` because
 * each TMM instance is its own process. */
static struct ls_slot g_slots[LS_MAX_SLOTS];
static bool           g_ready;

/* What PREVAIL was told, and therefore what uBPF must allocate. Passed to uBPF
 * as the calculator cookie so the two agree by construction rather than by two
 * defaults coincidentally matching (item 6a; see vm_stack_policy.h). */
static const struct vm_stack_policy g_policy = { .proven_frame = 256, .max_depth = 8 };

static struct ls_vm_config g_cfg;

/* Where the program came from, for the arm-time log. Knowing WHICH shield a pod
 * is running has already been a question once; it should never be a guess. */
static char g_origin[160];

/*
 * Read the timestamp counter. Used only when LS_VM_TIMING or LS_VM_BENCH is on,
 * so the shipped path is untouched by default.
 *
 * This is a CYCLE COUNT, not a duration, and the two are not interchangeable on
 * a machine that scales frequency. It is the right primitive for comparing two
 * paths on one box; it is the wrong primitive for quoting nanoseconds. The
 * aarch64 counter is worse still --- 10-40ns granularity against a budget of
 * tens of ns (finding O6) --- which is why any arm64 number from this needs its
 * own caveat rather than the same one.
 */
static inline uint64_t
ls_cycles(void)
{
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t v;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

/* Read a program from a file instead of the compiled-in blob. This is what turns
 * "change the shield" from a rebuild into a restart. Bounded: a program that
 * does not fit the cap is refused rather than truncated, because a truncated
 * ELF that happens to parse is worse than no program. */
#define LS_MAX_PROG 262144

/* Allocated for the file's actual size, at init, and freed once the program is
 * loaded into the VM. A static buffer here is permanently-resident .bss in every
 * TMM instance --- one per core --- holding a copy of something uBPF has already
 * copied. Measured: the static version cost 256 KB per instance for nothing. */
static unsigned char *g_filebuf;

static size_t
ls_read_program(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > LS_MAX_PROG) {
        fprintf(stderr, "ls_vm: %s is %ld bytes; limit is %d --- refusing rather "
                        "than truncating\n", path, sz, LS_MAX_PROG);
        fclose(f);
        return 0;
    }
    free(g_filebuf);
    g_filebuf = malloc((size_t)sz);
    if (g_filebuf == NULL) { fclose(f); return 0; }
    size_t n = fread(g_filebuf, 1, (size_t)sz, f);
    fclose(f);
    return (n == (size_t)sz) ? n : 0;
}

/* Adapter, not a cast. vm_stack_policy.h deliberately does not include uBPF's
 * headers --- it must stay checkable on its own --- so its calculator takes
 * `const void *` where uBPF's typedef takes `const struct ubpf_vm *`. Those are
 * DIFFERENT function pointer types, and calling through a converted incompatible
 * function pointer is undefined behaviour, not a style question. One forwarding
 * function costs nothing and keeps both sides honest. */
static int
ls_stack_usage(const struct ubpf_vm *vm, uint16_t pc, void *cookie)
{
    return vm_stack_usage((const void *)vm, pc, cookie);
}


/*
 * Does `function` live in `section` within this object? (Finding O14.)
 *
 * PREVAIL is told a SECTION and proves the program there. uBPF is told a FUNCTION
 * SYMBOL and runs that. Nothing in either tool relates the two, so an object with
 * more than one function can be verified as one program and executed as another.
 * This closes that by reading the object's own symbol table.
 *
 * Written defensively on purpose: `elf_len` is attacker-influenced in the real
 * loader path, so every offset is bounds-checked against it before use. Returns
 * 1 only when the relationship is positively established --- unknown is a refusal,
 * not a pass.
 */
static int
ls_symbol_is_in_section(const void *elf, size_t elf_len,
                        const char *section, const char *function)
{
    const unsigned char *base = (const unsigned char *)elf;

    if (elf == NULL || section == NULL || function == NULL)
        return 0;
    if (elf_len < sizeof(Elf64_Ehdr))
        return 0;

    Elf64_Ehdr eh;
    memcpy(&eh, base, sizeof eh);
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64)
        return 0;
    if (eh.e_shentsize != sizeof(Elf64_Shdr) || eh.e_shnum == 0)
        return 0;
    /* section header table must lie wholly inside the object */
    if (eh.e_shoff > elf_len ||
        (size_t)eh.e_shnum * sizeof(Elf64_Shdr) > elf_len - (size_t)eh.e_shoff)
        return 0;
    if (eh.e_shstrndx >= eh.e_shnum)
        return 0;

    const Elf64_Shdr *sh = (const Elf64_Shdr *)(const void *)(base + eh.e_shoff);

    /* section-name string table */
    const Elf64_Shdr *shstr = &sh[eh.e_shstrndx];
    if (shstr->sh_offset > elf_len || shstr->sh_size > elf_len - shstr->sh_offset)
        return 0;
    const char *shstrtab = (const char *)(base + shstr->sh_offset);

    /* find the symbol table and its string table */
    const Elf64_Shdr *symtab = NULL;
    for (unsigned i = 0; i < eh.e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB) { symtab = &sh[i]; break; }
    }
    if (symtab == NULL || symtab->sh_entsize != sizeof(Elf64_Sym))
        return 0;
    if (symtab->sh_offset > elf_len || symtab->sh_size > elf_len - symtab->sh_offset)
        return 0;
    if (symtab->sh_link >= eh.e_shnum)
        return 0;

    const Elf64_Shdr *strh = &sh[symtab->sh_link];
    if (strh->sh_offset > elf_len || strh->sh_size > elf_len - strh->sh_offset)
        return 0;
    const char *strtab = (const char *)(base + strh->sh_offset);

    const Elf64_Sym *sym = (const Elf64_Sym *)(const void *)(base + symtab->sh_offset);
    size_t nsyms = (size_t)(symtab->sh_size / sizeof(Elf64_Sym));

    for (size_t i = 0; i < nsyms; i++) {
        if (sym[i].st_name >= strh->sh_size)
            continue;                       /* name would run off the string table */
        if (strcmp(strtab + sym[i].st_name, function) != 0)
            continue;
        if (ELF64_ST_TYPE(sym[i].st_info) != STT_FUNC)
            continue;                       /* a data symbol of the same name is not it */
        if (sym[i].st_shndx >= eh.e_shnum)
            return 0;                       /* SHN_UNDEF / ABS: not defined here */

        const Elf64_Shdr *owner = &sh[sym[i].st_shndx];
        if (owner->sh_name >= shstr->sh_size)
            return 0;
        return strcmp(shstrtab + owner->sh_name, section) == 0;
    }
    return 0;                               /* no such function: refuse */
}

bool
ls_vm_init(void)
{
    memset(g_slots, 0, sizeof g_slots);
    ls_vm_config_load(&g_cfg);
    if (g_prog_stack == NULL) {
        g_prog_stack = calloc(1, LS_PROG_STACK_SIZE);
        if (g_prog_stack == NULL)
            return false;
    }
    if (!g_cfg.enable) {
        /* A shield that misbehaves must be switchable off without reverting the
         * integration and without a rebuild. */
        fprintf(stderr, "ls_vm: disabled by LS_SHIELD_ENABLE=0\n");
        return false;
    }
    g_ready = true;
    if (g_cfg.verbose)
        fprintf(stderr, "ls_vm: init  build=%s %s  jit=%d fuel=%u timing=%d\n",
                __DATE__, __TIME__, (int)g_cfg.jit, g_cfg.fuel, (int)g_cfg.timing);
    return true;
}

bool
ls_vm_stats(int slot, struct ls_stats *out)
{
    if (slot < 0 || slot >= LS_MAX_SLOTS || out == NULL)
        return false;
    const struct ls_slot *s = &g_slots[slot];
    out->armed = s->armed;
    out->mode = (int)s->mode;
    out->fired = s->fired;
    out->safe_returns = s->safe_returns;
    /* Counters are per SLOT and survive a program swap. That residue was read as
     * a result twice on 2026-08-17 --- a safe_returns=246 left by one program was
     * taken as evidence about the next. `gen` increments on every reload, so a
     * reader can tell whether the counts belong to the program it just loaded. */
    out->gen = s->gen;
    out->errors = s->errors;
    out->cycles = s->cycles;
    out->cycles_max = s->cycles_max;
    return true;
}

unsigned
ls_vm_samples(int slot, struct ls_ctx_sample *out, unsigned max)
{
    if (slot < 0 || slot >= LS_MAX_SLOTS || out == NULL)
        return 0;
    struct ls_slot *s = &g_slots[slot];
    unsigned have = s->sample_next < LS_CTX_SAMPLES ? (unsigned)s->sample_next
                                                    : LS_CTX_SAMPLES;
    if (have > max)
        have = max;
    for (unsigned i = 0; i < have; i++)
        out[i] = s->samples[i];
    return have;
}

/*
 * Load a program, benchmark it, throw it away --- WITHOUT arming it onto a hook.
 *
 * Move-3 instrument. Calibrating the budget pass needs the measured cost of many
 * programs of varying length and opcode mix. Doing that through LS_SHIELD_PATH
 * costs a pod restart per data point; doing it here costs a message. That is the
 * difference between fitting a model and sampling twice and guessing.
 *
 * Runs on the loader thread, off the data path, and never touches a live slot.
 */
int
ls_vm_bench_program(const void *elf, size_t elf_len,
                    const char *section, const char *function,
                    uint32_t iters,
                    uint64_t *min_out, uint64_t *mean_out, uint64_t *max_out)
{
    char *err = NULL;
    struct ubpf_vm *vm = NULL;
    uint8_t *stack = NULL;
    unsigned char ctx[64];
    uint64_t ret = 0, best = ~0ull, worst = 0, total = 0;
    int rc = -1;

    if (elf == NULL || iters == 0)
        return -1;
    if (!ls_symbol_is_in_section(elf, elf_len, section, function))
        return -1;                          /* same O14 gate as the real path */

    vm = ubpf_create();
    if (vm == NULL)
        return -1;
    if (ubpf_register_stack_usage_calculator(vm, ls_stack_usage, (void *)&g_policy) != 0)
        goto out;
    /* Maps, before the load --- the bench path needs it for the same reason the
     * arm path does: a program with maps must measure with its maps working, or
     * the number describes a program that fell through every lookup. */
    if (ls_map_glue_install(vm) != 0)
        goto out;
    if (ubpf_load_elf_ex(vm, elf, elf_len, function, &err) < 0)
        goto out;

    /* Its own stack: the shared one belongs to the data path, and this runs on
     * the loader thread. */
    stack = calloc(1, LS_PROG_STACK_SIZE);
    if (stack == NULL)
        goto out;

    memset(ctx, 0, sizeof ctx);
    for (uint32_t i = 0; i < 100 && i < iters; i++)
        (void)ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, LS_PROG_STACK_SIZE);

    for (uint32_t i = 0; i < iters; i++) {
        uint64_t t0 = ls_cycles();
        if (ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, LS_PROG_STACK_SIZE) != 0)
            goto out;
        uint64_t d = ls_cycles() - t0;
        total += d;
        if (d < best)  best = d;
        if (d > worst) worst = d;
    }
    if (min_out)  *min_out  = best;
    if (mean_out) *mean_out = total / iters;
    if (max_out)  *max_out  = worst;
    rc = 0;
out:
    free(err);
    free(stack);
    if (vm) ubpf_destroy(vm);
    return rc;
}

void
ls_vm_report(void)
{
    for (int i = 0; i < LS_MAX_SLOTS; i++) {
        const struct ls_slot *s = &g_slots[i];
        if (!s->armed)
            continue;
        fprintf(stderr,
                "ls_vm: slot=%d mode=%d fired=%llu safe_returns=%llu errors=%llu"
                " cycles_total=%llu cycles_mean=%llu cycles_max=%llu\n",
                i, (int)s->mode,
                (unsigned long long)s->fired, (unsigned long long)s->safe_returns,
                (unsigned long long)s->errors, (unsigned long long)s->cycles,
                (unsigned long long)(s->fired ? s->cycles / s->fired : 0),
                (unsigned long long)s->cycles_max);
    }
}

/*
 * Run the program N times over a fixed ctx and report cycle statistics.
 *
 * This exists because the alternative --- waiting for live traffic to reach one
 * specific vulnerable function --- requires a listener configured with a
 * protocol-transfer log profile, which is a whole config exercise standing
 * between us and a number. The benchmark answers "what does one invocation
 * cost" directly.
 *
 * What it measures: ubpf_exec plus this function's own loop overhead, on a warm
 * cache, with no contention. That is the FLOOR. A real invocation adds the ctx
 * build, a cold-ish cache, and whatever the poll loop is doing. Report it as a
 * floor or not at all.
 */
static void
ls_vm_bench(int slot, uint32_t iters)
{
    struct ls_slot *s = &g_slots[slot];
    unsigned char ctx[64];
    uint64_t ret = 0, best = ~0ull, worst = 0, total = 0;

    if (!s->armed || iters == 0)
        return;
    memset(ctx, 0, sizeof ctx);        /* the NULL case: the shield's hot branch */

    ubpf_jit_ex_fn jf = (ubpf_jit_ex_fn)s->jit_fn;

    for (uint32_t i = 0; i < 100 && i < iters; i++)   /* warm */
        if (jf) (void)jf(ctx, sizeof ctx, g_prog_stack, LS_PROG_STACK_SIZE);
        else    (void)ubpf_exec_ex(s->vm, ctx, sizeof ctx, &ret, g_prog_stack, LS_PROG_STACK_SIZE);

    for (uint32_t i = 0; i < iters; i++) {
        uint64_t t0 = ls_cycles();
        int rc = 0;
        if (jf) ret = jf(ctx, sizeof ctx, g_prog_stack, LS_PROG_STACK_SIZE);
        else    rc  = ubpf_exec_ex(s->vm, ctx, sizeof ctx, &ret, g_prog_stack, LS_PROG_STACK_SIZE);
        uint64_t d = ls_cycles() - t0;
        if (rc != 0) { fprintf(stderr, "ls_vm: bench exec fault at %u\n", i); return; }
        total += d;
        if (d < best)  best = d;
        if (d > worst) worst = d;
    }
    fprintf(stderr,
            "ls_vm: bench slot=%d path=%s iters=%u min=%llu mean=%llu max=%llu cycles"
            "  (floor: warm cache, no contention, ubpf_exec only --- NOT a"
            " per-packet cost)\n",
            slot, jf ? "JIT" : "interp", iters, (unsigned long long)best,
            (unsigned long long)(total / iters), (unsigned long long)worst);
}

int
ls_vm_arm(const void *elf, size_t elf_len,
          const char *section, const char *function, enum ls_mode m)
{
    int slot = -1;
    char *err = NULL;

    if (!g_ready || elf == NULL || section == NULL || function == NULL)
        return -1;

    /* O14: the verifier proved the program in `section`; uBPF is about to run the
     * one named `function`. Refuse unless they are the same program. */
    if (!ls_symbol_is_in_section(elf, elf_len, section, function)) {
        fprintf(stderr, "ls_vm: refusing --- '%s' does not live in section '%s'; "
                        "the verified program and the loaded one may differ\n",
                function, section);
        return -1;
    }

    for (int i = 0; i < LS_MAX_SLOTS; i++) {
        if (!g_slots[i].armed) { slot = i; break; }
    }
    if (slot < 0)
        return -1;

    struct ubpf_vm *vm = ubpf_create();
    if (vm == NULL)
        return -1;

    /* Before load: make the runtime allocate the frame the proof assumed.
     * Registering this is not optional --- without it uBPF falls back to 256
     * regardless of what the program was verified against, and a calculator
     * that returns 0 gets a ZERO-byte frame (finding O13). */
    if (ubpf_register_stack_usage_calculator(vm, ls_stack_usage, (void *)&g_policy) != 0)
        goto fail;

    /* Maps. MUST precede ubpf_load_elf_ex: the relocation callback is consulted
     * while uBPF walks the maps section, and a VM without it hands every helper
     * map=0 --- a program that loads, verifies, runs, and whose maps are silently
     * always empty. That is exactly the state this build was in. */
    if (ls_map_glue_install(vm) != 0)
        goto fail;

    /* Interpreter by default. The JIT is reachable by env var so its cost can be
     * MEASURED without a rebuild --- not because it is safe to run (O6: fuel has
     * no effect once JIT'd; O7: the prologue opens a 4KB frame with no probe). */
    /* uBPF selects by FUNCTION SYMBOL here, not section --- see O14 and the
     * check above, which is what makes passing `function` safe. */
    if (ubpf_load_elf_ex(vm, elf, elf_len, function, &err) < 0)
        goto fail;

    /* Fuel. Works in the interpreter; documented as having no effect once
     * compiled to native code, which is the other half of why this is the
     * interpreter path first. */
    ubpf_set_instruction_limit(vm, g_cfg.fuel ? g_cfg.fuel : 10000, NULL);

    if (g_cfg.jit) {
        char *jerr = NULL;
        /* ubpf_exec/_ex ALWAYS interpret --- they never dispatch to compiled
         * code. A JIT'd program is reached only through the function pointer
         * ubpf_compile returns, so storing it is what makes the JIT do anything
         * at all. Compiling and then calling ubpf_exec, as an earlier version of
         * this file did, JITs the program and throws the result away: the
         * measurement showed jit=1 and jit=0 within noise of each other, which
         * was the tell. */
        /* EXTENDED mode, not basic. Basic mode's generated prologue allocates
         * its own stack --- ubpf.h: "automatically allocates a stack" --- which
         * is the unprobed 4 KB frame finding O7 is about. Extended mode takes the
         * stack as an argument, so the same per-instance buffer serves both the
         * interpreter and the compiled path. */
        g_slots[slot].jit_fn = (void *)ubpf_compile_ex(vm, &jerr, ExtendedJitMode);
        if (g_slots[slot].jit_fn == NULL) {
            fprintf(stderr, "ls_vm: JIT requested but failed: %s\n", jerr ? jerr : "?");
            free(jerr);
            goto fail;
        }
    }

    g_slots[slot].vm    = vm;
    g_slots[slot].mode  = m;
    g_slots[slot].armed = true;

    if (g_cfg.verbose)
        fprintf(stderr, "ls_vm: ARMED slot=%d section=%s function=%s mode=%d"
                        " bytes=%lu origin=%s jit=%d\n",
                slot, section, function, (int)m, (unsigned long)elf_len,
                g_origin[0] ? g_origin : "builtin", (int)g_cfg.jit);

    if (g_cfg.bench)
        ls_vm_bench(slot, g_cfg.bench);

    if (g_cfg.selftest)
        ls_vm_selftest(slot, g_cfg.selftest);

    return slot;

fail:
    if (err) { fprintf(stderr, "ls_vm: arm failed: %s\n", err); free(err); }
    ubpf_destroy(vm);
    return -1;
}

/*
 * Reproduce the CVE condition against the armed shield --- LS_VM_SELFTEST.
 *
 * WHAT THIS DEMONSTRATES: the real verified program, in the real VM, inside the
 * real TMM binary, deciding on the exact input the vulnerable call site would
 * hand it --- a NULL protocol-transfer log profile. And, at level 2, that the
 * dereference which follows a FALLTHROUGH verdict really is fatal.
 *
 * WHAT IT DOES NOT DEMONSTRATE, and must not be reported as: that the hook is
 * correctly placed in http_psm_profile_name_lookup, or that live traffic reaches
 * it. Those are separate claims needing a configured listener and a security log
 * profile whose format string contains ${profile_name}. This synthesises the
 * condition; it does not drive the path.
 *
 * Deliberately not built from fake TMM structures. Walking
 * log_data->scb->uf -> connflow -> listener would mean synthesising four internal
 * types, and a crash inside flow_get_listener() would prove nothing about this
 * bug. The ctx is what the shield actually sees, so the ctx is what is reproduced.
 *
 *   LS_VM_SELFTEST=1  evaluate and report. Never crashes.
 *   LS_VM_SELFTEST=2  evaluate, and on FALLTHROUGH perform the real dereference.
 *                     With the shield armed this survives; with LS_SHIELD_ENABLE=0
 *                     it is a segfault. That difference is the whole demonstration.
 */
static void
ls_vm_selftest(int slot, unsigned level)
{
    /* Exactly the ctx the call site builds when the listener has no profile. */
    struct { uint64_t ptlp, ptlp_name; uint32_t key, name_len; } c;
    memset(&c, 0, sizeof c);          /* ptlp == NULL --- the CVE condition */

    enum ls_verdict v = ls_vm_call(slot, &c, sizeof c);

    fprintf(stderr,
            "ls_vm: SELFTEST cve-condition ptlp=NULL -> verdict=%s  (%s)\n",
            v == LS_SAFE_RETURN ? "SAFE_RETURN" : "FALLTHROUGH",
            v == LS_SAFE_RETURN
              ? "the shield would skip the body --- no dereference, no crash"
              : "the body would run --- the NULL dereference happens next");

    if (level < 2)
        return;

    if (v == LS_SAFE_RETURN) {
        fprintf(stderr, "ls_vm: SELFTEST survived --- shield prevented the "
                        "dereference. Re-run with LS_SHIELD_ENABLE=0 to see the "
                        "same binary crash.\n");
        return;
    }

    /* No shield, or it declined. Do what the vulnerable line does. */
    fprintf(stderr, "ls_vm: SELFTEST performing the unshielded dereference --- "
                    "this is expected to be fatal\n");
    fflush(stderr);
    {
        volatile const char *const *pp = (volatile const char *const *)(uintptr_t)c.ptlp;
        volatile char sink = *(*pp);      /* ptlp->name, with ptlp == NULL */
        (void)sink;
    }
    fprintf(stderr, "ls_vm: SELFTEST did NOT crash --- unexpected; the platform "
                    "may be mapping page zero\n");
}

int
ls_vm_arm_configured(const void *blob, size_t blob_len,
                     const char *section, const char *function)
{
    const void *prog = blob;
    size_t      len  = blob_len;

    if (!g_ready)
        return -1;

    /* A program on disk replaces the compiled-in one. Refusing on a bad path
     * rather than silently falling back to the built-in matters: an operator who
     * pointed at a file and got the old shield, with no error, would have no way
     * to tell which program is running. */
    if (g_cfg.path) {
        size_t n = ls_read_program(g_cfg.path);
        if (n == 0) {
            fprintf(stderr, "ls_vm: LS_SHIELD_PATH=%s unreadable or empty --- "
                            "refusing (NOT falling back to the built-in)\n", g_cfg.path);
            return -1;
        }
        prog = g_filebuf;
        len  = n;
        /* uBPF copies the program during load, so this buffer is dead after
         * ls_vm_arm returns --- freed below rather than held for the process
         * lifetime. */
        snprintf(g_origin, sizeof g_origin, "file:%s(%lu)", g_cfg.path, (unsigned long)n);
    } else {
        snprintf(g_origin, sizeof g_origin, "builtin(%lu)", (unsigned long)len);
    }

    int slot = ls_vm_arm(prog, len,
                         g_cfg.section  ? g_cfg.section  : section,
                         g_cfg.function ? g_cfg.function : function,
                         (enum ls_mode)g_cfg.mode);
    free(g_filebuf);
    g_filebuf = NULL;
    return slot;
}

enum ls_verdict
ls_vm_call(int slot, void *ctx, size_t ctx_len)
{
    uint64_t ret = 0;

    if (slot < 0 || slot >= LS_MAX_SLOTS)
        return LS_FALLTHROUGH;

    struct ls_slot *s = &g_slots[slot];

    /* Both of these can be replaced under us by the loader thread, so read each
     * exactly once. Reading s->vm twice could straddle a swap and use one
     * program's VM with another's expectations. */
    enum ls_mode mode = __atomic_load_n(&s->mode, __ATOMIC_ACQUIRE);
    void *vm = __atomic_load_n(&s->vm, __ATOMIC_ACQUIRE);
    if (!s->armed || vm == NULL || mode == LS_MODE_DISABLE)
        return LS_FALLTHROUGH;

    /* A non-zero return from ubpf_exec is an execution fault --- fuel exhausted,
     * or a bounds check the interpreter enforces at run time. Fall through: a
     * shield that cannot run must not take the flow with it. Counted, because a
     * silent fail-open is indistinguishable from a shield that never matched. */
    uint64_t t0 = g_cfg.timing ? ls_cycles() : 0;
    /* Compiled path if we have one, interpreter otherwise. Both take the stack
     * from us: ubpf_exec would allocate and touch 4 KB of C stack on every packet
     * reaching this hook, and basic-mode JIT code would do the same in its
     * prologue without a guard-page probe (O7). */
    int rc = 0;
    void *jf = __atomic_load_n(&s->jit_fn, __ATOMIC_ACQUIRE);
    if (jf != NULL) {
        ret = ((ubpf_jit_ex_fn)jf)(ctx, ctx_len, g_prog_stack, LS_PROG_STACK_SIZE);
    } else {
        rc = ubpf_exec_ex(vm, ctx, ctx_len, &ret, g_prog_stack, LS_PROG_STACK_SIZE);
    }
    if (g_cfg.timing) {
        uint64_t d = ls_cycles() - t0;
        s->cycles += d;
        if (d > s->cycles_max)
            s->cycles_max = d;
    }
    if (rc != 0) {
        s->errors++;
        return LS_FALLTHROUGH;
    }

    /* Sample the ctx. A fixed-size memcpy into a slot-resident ring: no
     * allocation, no lock, no syscall. Gated so the shipped path is untouched
     * unless asked --- same discipline as timing. */
    if (g_cfg.samples) {
        struct ls_ctx_sample *sm = &s->samples[s->sample_next % LS_CTX_SAMPLES];
        size_t n = ctx_len < LS_CTX_SAMPLE_BYTES ? ctx_len : LS_CTX_SAMPLE_BYTES;
        sm->seq = s->fired;
        sm->len = (uint32_t)ctx_len;
        sm->verdict = (uint32_t)ret;
        memcpy(sm->bytes, ctx, n);
        s->sample_next++;
    }

    if (s->fired == 0 && g_cfg.verbose)
        fprintf(stderr, "ls_vm: FIRST INVOCATION slot=%d --- the hook is reached\n", slot);
    s->fired++;
    if (g_cfg.report_every && (s->fired % g_cfg.report_every) == 0)
        ls_vm_report();

    if (ret != LS_SAFE_RETURN)
        return LS_FALLTHROUGH;

    s->safe_returns++;

    /* Monitor mode counts the selection and applies nothing. The counters above
     * are what make a monitor-mode hit distinguishable from a miss. */
    return (mode == LS_MODE_ENFORCE) ? LS_SAFE_RETURN : LS_FALLTHROUGH;
}

/*
 * Publish a new program over a live slot. The whole point of this function is
 * the ORDER: everything expensive and everything fallible happens first, into
 * storage the data path cannot see, and the data path only ever observes a
 * single pointer store that is either the old program or the new one.
 *
 * What this is NOT: the ordered cross-core publish of item 0. A call already in
 * flight keeps the VM it loaded at entry; the next call gets the new one. That
 * is atomic-per-call replacement, which is sufficient for one hook and one
 * program and is not sufficient for a coordinated multi-hook update.
 *
 * The old VM is deliberately LEAKED. Freeing it needs proof that no core is
 * still inside it --- items 0b/0c --- and a wrong free here is a use-after-free
 * on the data path. Leaking is bounded by the number of loads and cannot
 * corrupt anything; a load loop would exhaust memory, which is a real limit
 * stated rather than hidden.
 */
int
ls_vm_reload(int slot, const void *elf, size_t elf_len,
             const char *section, const char *function, enum ls_mode m)
{
    if (slot < 0 || slot >= LS_MAX_SLOTS || !g_ready)
        return -1;

    /* Prepare into a spare slot: create, identity-check, load, JIT if asked.
     * All of it off the data path, all of it able to fail harmlessly. */
    int staged = ls_vm_arm(elf, elf_len, section, function, m);
    if (staged < 0)
        return -1;
    if (staged == slot)
        return slot;                      /* nothing was live here */

    struct ls_slot *live = &g_slots[slot];
    struct ls_slot *new  = &g_slots[staged];

    /* The publish. Release-ordered so each object's contents are visible to any
     * core that observes the pointer.
     *
     * jit_fn MUST be published with vm, and this is not a detail. ls_vm_call
     * prefers jit_fn whenever it is non-NULL and only falls back to the
     * interpreter when it is NULL --- so a swap that replaced vm alone left the
     * PREVIOUS program's compiled code executing while the new program sat in an
     * interpreter nothing ever consulted. Every load over the socket appeared to
     * succeed, the counters moved, and the resident program kept answering. The
     * two observable symptoms were a verdict that ignored the loaded program and
     * a slot whose behaviour never changed no matter what was sent to it.
     *
     * Order matters for a core already inside ls_vm_call:
     *   1. mode  -> DISABLE   readers take the early-out and fall through
     *   2. jit_fn-> NULL      no reader can enter the OLD compiled code
     *   3. vm    -> new       the interpreter now backs this slot
     *   4. jit_fn-> new       compiled path returns, matching the new vm
     *   5. mode  -> m         the slot goes live again
     * Steps 2-4 are what make (vm, jit_fn) observably one program rather than
     * two. A reader that sampled the old jit_fn before step 2 runs old compiled
     * code to completion, which is safe only because the old VM is leaked rather
     * than destroyed --- the code it points at stays mapped. That known debt
     * (item 0c) is load-bearing here; reclaiming it needs the quiescence pass,
     * not a free() in this function. */
    __atomic_store_n(&live->mode, LS_MODE_DISABLE, __ATOMIC_RELAXED);
    __atomic_store_n(&live->jit_fn, NULL, __ATOMIC_RELEASE);
    __atomic_store_n(&live->vm, new->vm, __ATOMIC_RELEASE);   /* old VM leaked */
    __atomic_store_n(&live->jit_fn, new->jit_fn, __ATOMIC_RELEASE);
    __atomic_store_n(&live->mode, m, __ATOMIC_RELEASE);
    live->armed = true;
    live->gen++;              /* so STATUS can distinguish residue from result */

    new->armed = false;                   /* the staging slot goes back */
    new->vm = NULL;
    new->jit_fn = NULL;

    fprintf(stderr, "ls_vm: RELOADED slot=%d mode=%d bytes=%lu "
                    "(previous VM leaked --- reclamation is item 0c)\n",
            slot, (int)m, (unsigned long)elf_len);
    return slot;
}

void
ls_vm_set_mode(int slot, enum ls_mode m)
{
    if (slot < 0 || slot >= LS_MAX_SLOTS)
        return;
    __atomic_store_n(&g_slots[slot].mode, m, __ATOMIC_RELEASE);
    fprintf(stderr, "ls_vm: slot=%d mode -> %d\n", slot, (int)m);
}

void
ls_vm_fini(void)
{
    ls_vm_report();
    for (int i = 0; i < LS_MAX_SLOTS; i++) {
        if (g_slots[i].armed) {
            ubpf_destroy(g_slots[i].vm);
            g_slots[i].armed = false;
        }
    }
    g_ready = false;
}
