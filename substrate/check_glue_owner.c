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
    assert(strcmp(calls, "reloc bounds h1 h2 h3 h5 h25 ") == 0);
    printf("ok    install order: %s\n", calls);

    /* --- 3. the non-owning TU installs identically ------------------------- */
    reset();
    assert(user_install(&fake_vm) == 0);
    assert(strcmp(calls, "reloc bounds h1 h2 h3 h5 h25 ") == 0);
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
    /* SEVEN registrations now: reloc, bounds, and helpers 1/2/3/5/130. The clock and the
     * ringbuf helper are part of the same all-or-nothing set on purpose --- a VM that
     * resolved a ringbuf map and then had no helper to emit through would give a program
     * that verifies, runs, and silently drops everything it tried to publish. */
    for (k = 0; k < 7; k++) {
        reset();
        fail_at = k;
        assert(owner_install(&fake_vm) == -1);
    }
    printf("ok    install is all-or-nothing at each of the 7 registrations\n");

    /* --- 6. MAP IDENTITY IS THE NAME, NOT THE SHAPE -----------------------
     * The dedup used to compare (key_size, value_size, max_entries) only. Correct
     * within one program --- clang emits one relocation per reference --- and
     * wrong across programs, because the shape table is process-global. Two
     * unrelated programs each declaring a 4/8/64 map got the SAME index and so
     * the same per-thread storage, each reading the other's counts as its own.
     * Silent: shared state looks like a counter running high.
     *
     * These build a maps section by hand and call the relocation callback the way
     * ubpf_load_elf_ex does. What is asserted is mostly REFUSAL, because every
     * failure in this callback resolves to a plausible index rather than an
     * error. */
    {
        struct ls_map_def a = { LS_MAP_TYPE_HASH, 4u, 8u, 64u, 0u };
        struct ls_map_def b = { LS_MAP_TYPE_HASH, 8u, 8u, 64u, 0u };  /* same name,
                                                                       * other shape */
        unsigned char sec[3 * sizeof(struct ls_map_def)];
        const uint64_t REFUSED = (uint64_t)LS_MAP_MAX + 1u;
        char longname[LS_MAP_NAME_MAX + 8];
        uint64_t i0, i1;

        memcpy(sec + 0 * sizeof a, &a, sizeof a);
        memcpy(sec + 1 * sizeof a, &a, sizeof a);
        memcpy(sec + 2 * sizeof a, &b, sizeof b);

        ls_map_reset_shapes();
        assert(atomic_load(&g_ls_nshapes) == 0u);

        /* First reference to "rate" takes an index. */
        i0 = ls_map_reloc(NULL, sec, sizeof sec, "rate", 0, sizeof a);
        assert(i0 < LS_MAP_MAX);

        /* Second reference to the SAME name and shape resolves to the SAME index
         * --- this is the within-program dedup, still required. */
        assert(ls_map_reloc(NULL, sec, sizeof sec, "rate", 0, sizeof a) == i0);

        /* THE FIX. An identically shaped map under a DIFFERENT name must get its
         * own index. Before the name key this returned i0 and the two programs
         * shared storage. */
        i1 = ls_map_reloc(NULL, sec, sizeof sec, "resets_seen",
                          1 * sizeof a, sizeof a);
        assert(i1 < LS_MAP_MAX);
        assert(i1 != i0);

        /* Same name, DIFFERENT shape: refused, never shared. Two programs that
         * disagree about a shared map's layout would both write it. */
        assert(ls_map_reloc(NULL, sec, sizeof sec, "rate",
                            2 * sizeof a, sizeof b) == REFUSED);

        /* No name at all: identity is undecidable, so neither sharing nor
         * privacy can be chosen correctly. Refuse rather than guess. */
        assert(ls_map_reloc(NULL, sec, sizeof sec, NULL, 0, sizeof a) == REFUSED);
        assert(ls_map_reloc(NULL, sec, sizeof sec, "",   0, sizeof a) == REFUSED);

        /* A name that would not round-trip through the table is refused rather
         * than truncated --- truncation turns two distinct maps into one. */
        memset(longname, 'x', sizeof longname - 1);
        longname[sizeof longname - 1] = '\0';
        assert(ls_map_reloc(NULL, sec, sizeof sec, longname, 0, sizeof a) == REFUSED);

        /* Reset clears NAMES too. A name surviving at an index the next load
         * reuses would match a map it has nothing to do with --- which is the
         * aliasing this change removes, reintroduced by the reset path. */
        ls_map_reset_shapes();
        for (k = 0; k < (int)LS_MAP_MAX; k++)
            assert(g_ls_names[k][0] == '\0');

        printf("ok    map identity is the NAME: same name+shape shares, "
               "different name is private, name+other shape REFUSED\n");
    }

    /* --- 7. THE CLOCK ------------------------------------------------------
     * The most useful addition in the inventory, because without it a program cannot
     * express "N per second" and every threshold means "ever". Two properties matter: it
     * must not return 0 (a program comparing against 0 sees no elapsed time, so every
     * limiter opens), and it must not go backwards. */
    {
        uint64_t t1 = ls_h_ktime_get_ns(0, 0, 0, 0, 0);
        uint64_t t2 = ls_h_ktime_get_ns(0, 0, 0, 0, 0);
        assert(t1 != 0);
        assert(t2 >= t1);          /* MONOTONIC, so this cannot regress */
        printf("ok    bpf_ktime_get_ns non-zero and never regresses (MONOTONIC, not "
               "REALTIME --- a clock step must not open every limiter)\n");
    }

    /* --- 8. THE EMIT HELPER, and mostly its REFUSALS ------------------------
     * Every guard returns before touching the ring. The stub counts what gets through, so
     * "publish did not happen" is asserted rather than assumed. */
    {
        extern int ls_tp_publish_calls;
        extern unsigned long ls_tp_publish_len;
        const uint64_t REFUSED = (uint64_t)-1;
        struct ls_map_def rb = { LS_MAP_TYPE_PERF_EVENT_ARRAY, 4u, 4u, 16u, 0u };
        struct ls_map_def hs = { LS_MAP_TYPE_HASH, 4u, 8u, 64u, 0u };
        unsigned char sec[2 * sizeof(struct ls_map_def)];
        unsigned char payload[64];
        uint64_t ring_idx, hash_idx;

        memcpy(sec, &rb, sizeof rb);
        memcpy(sec + sizeof rb, &hs, sizeof hs);
        memset(payload, 0x5a, sizeof payload);

        ls_map_reset_shapes();
        g_ls_maps = 0;                 /* force this thread's storage to be rebuilt */
        g_ls_maps_failed = 0;

        /* A RINGBUF descriptor must be ADMITTED: key_size and value_size are 0, which the
         * hash checks correctly refuse, so it needs its own path. */
        ring_idx = ls_map_reloc(NULL, sec, sizeof sec, "ring", 0, sizeof rb);
        assert(ring_idx < LS_MAP_MAX);
        hash_idx = ls_map_reloc(NULL, sec, sizeof sec, "counts", sizeof rb, sizeof hs);
        assert(hash_idx < LS_MAP_MAX && hash_idx != ring_idx);

        ls_tp_publish_calls = 0;
        g_ls_cur_slot = 5;

        assert(ls_h_perf_event_output(0, ring_idx, 0, (uint64_t)(uintptr_t)payload, 0) == REFUSED);
        assert(ls_h_perf_event_output(0, ring_idx, 0, (uint64_t)(uintptr_t)payload, LS_RB_MAX_RECORD + 1) == REFUSED);
        assert(ls_h_perf_event_output(0, ring_idx, 0, 0, 8) == REFUSED);
        /* A HASH map is not a ring --- emitting through one would publish table bytes. */
        assert(ls_h_perf_event_output(0, hash_idx, 0, (uint64_t)(uintptr_t)payload, 8) == REFUSED);
        assert(ls_h_perf_event_output(0, LS_MAP_MAX + 5, 0, (uint64_t)(uintptr_t)payload, 8) == REFUSED);
        assert(ls_tp_publish_calls == 0);   /* not one of those reached the ring */

        /* No program running --- reached from anywhere else, refuse. */
        g_ls_cur_slot = -1;
        assert(ls_h_perf_event_output(0, ring_idx, 0, (uint64_t)(uintptr_t)payload, 8) == REFUSED);
        assert(ls_tp_publish_calls == 0);

        /* And the one case that SHOULD publish. */
        g_ls_cur_slot = 5;
        assert(ls_h_perf_event_output(0, ring_idx, 0, (uint64_t)(uintptr_t)payload, 32) == 0);
        assert(ls_tp_publish_calls == 1);
        assert(ls_tp_publish_len == 32);

        /* A hash operation on the RING slot must be an explicit no-op, not zero-size
         * arithmetic that happens to work out. */
        {
            struct ls_map *rm = ls_map_get(ls_map_current(), ring_idx);
            uint32_t key = 1; uint64_t val = 2;
            assert(rm != 0 && rm->is_ring);
            assert(ls_map_lookup(rm, (const uint8_t *)&key) == 0);
            assert(ls_map_update(rm, (const uint8_t *)&key, (const uint8_t *)&val) != 0);
            assert(ls_map_delete(rm, (const uint8_t *)&key) != 0);
        }
        printf("ok    bpf_ringbuf_output: 6 refusals (size 0, oversize, NULL, hash map, "
               "bad index, no program), 1 publish, hash ops on a ring refuse\n");
    }

    printf("ok    check_glue: 24 assertions\n");
    return 0;
}
