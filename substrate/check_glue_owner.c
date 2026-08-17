/* check_glue_owner.c --- the owning TU, and the assertions.
 *
 * WHAT THIS EXISTS TO CATCH. On 2026-08-17 the five uBPF registrations that make
 * maps work lived only in the build box's copy of ls_vm.c and were never carried
 * back into the repo. Copying the repo over that tree deleted them. Nothing
 * failed: programs loaded, PREVAIL verified them, they ran, and every map lookup
 * returned NULL --- indistinguishable from a predicate that never matches. The
 * live "maps work" result had been produced by an earlier binary that still had
 * the calls.
 *
 * Two things had to change for that to be catchable, and both are tested here:
 *
 *   1. The five calls became ONE call, ls_map_glue_install(). A five-step
 *      sequence duplicated across two arm paths can be half-applied or half-lost.
 *   2. The glue's state stopped being `static` in a header. It was safe only
 *      because exactly one file happened to include it; the install function
 *      means two now do, and `static` would have given each its own array.
 *
 * The link itself is part of the test. Two TUs include the header, one defines
 * LS_MAP_GLUE_IMPL, and if both ever did the link fails on a duplicate symbol.
 */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

extern unsigned user_nshapes(void);
extern int      user_install(void *vm);
extern char     calls[];
extern int      ncalls, fail_at;

int
owner_install(void *vm)
{
    return ls_map_glue_install((struct ubpf_vm *)vm);
}

static void
reset(void)
{
    calls[0] = 0;
    ncalls   = 0;
    fail_at  = -1;
}

int
main(void)
{
    struct { int unused; } fake_vm;
    int k;

    /* --- 1. ONE array, two TUs -------------------------------------------- */
    g_ls_shapes[0].key_size = 0xABCDu;
    assert(g_ls_shapes[0].key_size == 0xABCDu);
    assert(user_nshapes() == 0u);       /* reachable from the non-owning TU too */
    printf("ok    two TUs share ONE g_ls_shapes (a static in the header gave each its own)\n");

    /* --- 2. all five registrations, relocation FIRST ----------------------
     * Order is not cosmetic. ubpf_load_elf_ex walks the maps section and asks
     * the relocation callback there; registered afterwards it is never asked,
     * every `lddw` keeps the zero clang emitted, and every helper receives
     * map=0. That program loads, verifies and runs with maps always empty. */
    reset();
    assert(owner_install(&fake_vm) == 0);
    assert(strcmp(calls, "reloc bounds h1 h2 h3 ") == 0);
    printf("ok    install order: %s\n", calls);

    /* --- 3. the non-owning TU installs identically ------------------------- */
    reset();
    assert(user_install(&fake_vm) == 0);
    assert(strcmp(calls, "reloc bounds h1 h2 h3 ") == 0);
    printf("ok    non-owning TU installs identically (no divergence by includer)\n");

    /* --- 4. a NULL vm is refused before anything is registered ------------- */
    reset();
    assert(owner_install(NULL) == -1 && ncalls == 0);
    printf("ok    NULL vm refused, nothing registered\n");

    /* --- 5. all-or-nothing ------------------------------------------------
     * A VM with relocation but no bounds check resolves map indices and then
     * refuses every read of a value; one with helpers but no relocation hands
     * every helper map=0. Both look like a working feature. So any single
     * refusal must fail the whole install. */
    for (k = 0; k < 5; k++) {
        reset();
        fail_at = k;
        assert(owner_install(&fake_vm) == -1);
    }
    printf("ok    install is all-or-nothing at each of the 5 registrations\n");

    printf("ok    check_glue: 5 assertions\n");
    return 0;
}
