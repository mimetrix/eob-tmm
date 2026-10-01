/* Program ownership API. See PROGRAMS.md for the lifecycle and falsifiers.
 * The loader authenticates the ELF and all targets before calling load. */
#ifndef LS_PROGRAM_H
#define LS_PROGRAM_H
#include "ls_vm.h"
#include "ls_arm.h"

#define LS_PROGRAM_MAX 8
#define LS_PROGRAM_ENTRIES 12
#define LS_PROGRAM_SITES 12
#define LS_PROGRAM_CONFIG_BASE 56u
#define LS_PROGRAM_BINDING "@program-v1"

enum ls_program_op {
    LS_PROGRAM_LOAD = 0x2001,
    LS_PROGRAM_ATTACH,
    LS_PROGRAM_DETACH,
    LS_PROGRAM_MODE,
    LS_PROGRAM_REVOKE,
    LS_PROGRAM_STATUS
};

/* Control ops carry this exact payload. LOAD instead carries the signed ELF.
 * entry is zero for program-wide operations; reserved must always be zero. */
struct ls_program_request {
    uint64_t instance;
    uint32_t entry, reserved;
};
_Static_assert(sizeof(struct ls_program_request) == 16, "program control ABI");

struct ls_program_entry {
    char section[80];
    uint64_t address;
    unsigned pad;
};
struct ls_program_status {
    uint64_t instance;
    unsigned entries, attached, mode, config_slot;
};

/* Single control writer. A busy operation fails rather than waiting. */
int ls_program_load(unsigned program, const void *elf, size_t len,
                    const struct ls_program_entry *entries, unsigned count,
                    const uint8_t sha[32], unsigned ceiling);
int ls_program_status(unsigned program, struct ls_program_status *out);
int ls_program_mode(unsigned program, uint64_t instance, unsigned mode);
/* Patch callback: install=1 writes a call to site; install=0 restores NOPs.
 * It must refuse if another owner already uses the site or address. */
typedef int (*ls_program_patch_fn)(uint64_t address, unsigned site, int install);
int ls_program_attach(unsigned program, uint64_t instance, unsigned entry,
                      ls_program_patch_fn patch);
int ls_program_detach(unsigned program, uint64_t instance, unsigned entry,
                      ls_program_patch_fn patch);
int ls_program_revoke(unsigned program, uint64_t instance, ls_program_patch_fn patch);
int ls_program_site_owned(unsigned site, uint64_t address);
/* Returns 1 for a program-owned site, including a busy/disabled one. */
int ls_program_dispatch(unsigned site, uint64_t return_ip,
                        const struct ls_ctx_generic *input,
                        struct ls_tramp_result *out);
#endif
