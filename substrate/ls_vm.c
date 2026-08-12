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
#include "vm_stack_policy.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>   /* free() for uBPF's error strings */
#include <string.h>

#include "ubpf.h"

#define LS_MAX_SLOTS 8

/* Per TMM instance. Not shared, not locked --- see the header. `static` because
 * each TMM instance is its own process. */
static struct ls_slot g_slots[LS_MAX_SLOTS];
static bool           g_ready;

/* What PREVAIL was told, and therefore what uBPF must allocate. Passed to uBPF
 * as the calculator cookie so the two agree by construction rather than by two
 * defaults coincidentally matching (item 6a; see vm_stack_policy.h). */
static const struct vm_stack_policy g_policy = { .proven_frame = 256, .max_depth = 8 };

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
    g_ready = true;
    return true;
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

    /* Interpreter path. No ubpf_compile() here on purpose --- O6/O7. */
    /* uBPF selects by FUNCTION SYMBOL here, not section --- see O14 and the
     * check above, which is what makes passing `function` safe. */
    if (ubpf_load_elf_ex(vm, elf, elf_len, function, &err) < 0)
        goto fail;

    /* Fuel. Works in the interpreter; documented as having no effect once
     * compiled to native code, which is the other half of why this is the
     * interpreter path first. */
    ubpf_set_instruction_limit(vm, 10000, NULL);

    g_slots[slot].vm    = vm;
    g_slots[slot].mode  = m;
    g_slots[slot].armed = true;
    return slot;

fail:
    if (err) { fprintf(stderr, "ls_vm: arm failed: %s\n", err); free(err); }
    ubpf_destroy(vm);
    return -1;
}

enum ls_verdict
ls_vm_call(int slot, void *ctx, size_t ctx_len)
{
    uint64_t ret = 0;

    if (slot < 0 || slot >= LS_MAX_SLOTS)
        return LS_FALLTHROUGH;

    struct ls_slot *s = &g_slots[slot];
    if (!s->armed || s->mode == LS_MODE_DISABLE)
        return LS_FALLTHROUGH;

    /* A non-zero return from ubpf_exec is an execution fault --- fuel exhausted,
     * or a bounds check the interpreter enforces at run time. Fall through: a
     * shield that cannot run must not take the flow with it. */
    if (ubpf_exec(s->vm, ctx, ctx_len, &ret) != 0)
        return LS_FALLTHROUGH;

    s->fired++;

    if (ret != LS_SAFE_RETURN)
        return LS_FALLTHROUGH;

    s->safe_returns++;

    /* Monitor mode counts the selection and applies nothing. The counters above
     * are what make a monitor-mode hit distinguishable from a miss. */
    return (s->mode == LS_MODE_ENFORCE) ? LS_SAFE_RETURN : LS_FALLTHROUGH;
}

void
ls_vm_fini(void)
{
    for (int i = 0; i < LS_MAX_SLOTS; i++) {
        if (g_slots[i].armed) {
            ubpf_destroy(g_slots[i].vm);
            g_slots[i].armed = false;
        }
    }
    g_ready = false;
}
