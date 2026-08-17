/* Does the map do what the verifier assumed, and refuse what it must?
 *
 * PREVAIL proves the program passed a map descriptor and reads at most
 * value_size bytes of what lookup returned. It cannot prove the HOST resolves an
 * index to a map of that shape, nor that the bounds callback is right. Both are
 * ours, and both are asserted here.
 *
 * The refusals matter more than the successes. A descriptor we cannot honour must
 * be REFUSED rather than clamped -- clamping would leave the verifier having
 * proved bounds for a shape we do not enforce, which is the exact failure O14
 * exists to prevent one level down.
 */
#include <assert.h>
#include <stdio.h>
#include "ls_map.h"

int
main(void)
{
    static struct ls_map_set S;
    struct ls_map_def d = { LS_MAP_TYPE_HASH, 4, 8, 64, 0 };
    struct ls_map *m;
    int n = 0, idx;

    /* 1. a descriptor we can honour */
    idx = ls_map_create(&S, &d);
    assert(idx == 0);                                                        n++;
    m = ls_map_get(&S, 0);
    assert(m && m->key_sz == 4 && m->val_sz == 8 && m->entries == 64);       n++;

    /* 2. REFUSALS. Each is a shape PREVAIL might verify against but we cannot
     *    store, so each must be rejected rather than trimmed to fit. */
    { struct ls_map_def b = { 99, 4, 8, 64, 0 };                  /* wrong type */
      assert(ls_map_create(&S, &b) < 0);                                     n++; }
    { struct ls_map_def b = { LS_MAP_TYPE_HASH, 99, 8, 64, 0 };   /* key too big */
      assert(ls_map_create(&S, &b) < 0);                                     n++; }
    { struct ls_map_def b = { LS_MAP_TYPE_HASH, 4, 999, 64, 0 };  /* val too big */
      assert(ls_map_create(&S, &b) < 0);                                     n++; }
    { struct ls_map_def b = { LS_MAP_TYPE_HASH, 4, 8, 99999, 0 }; /* too many   */
      assert(ls_map_create(&S, &b) < 0);                                     n++; }
    { struct ls_map_def b = { LS_MAP_TYPE_HASH, 0, 8, 64, 0 };    /* zero key   */
      assert(ls_map_create(&S, &b) < 0);                                     n++; }

    /* 3. THE VALIDATION: an index a program could hand back. No pointer is ever
     *    involved, so this is the whole of it. */
    assert(ls_map_get(&S, 1) == 0);          /* not created */                n++;
    assert(ls_map_get(&S, 4) == 0);          /* past LS_MAP_MAX */            n++;
    assert(ls_map_get(&S, 0xdeadbeefULL) == 0);  /* garbage */                n++;

    /* 4. store and retrieve */
    {
        uint32_t k = 0x1234; uint64_t v = 42, *got;
        assert(ls_map_update(m, (uint8_t *)&k, (uint8_t *)&v) == 0);          n++;
        got = ls_map_lookup(m, (uint8_t *)&k);
        assert(got && *got == 42);                                           n++;
    }

    /* 5. a miss is a miss, not a stale hit */
    {
        uint32_t k = 0x9999;
        assert(ls_map_lookup(m, (uint8_t *)&k) == 0);                         n++;
    }

    /* 6. accumulate across calls --- the whole reason this exists */
    {
        uint32_t k = 7; uint64_t one = 1, *v; int i;
        ls_map_update(m, (uint8_t *)&k, (uint8_t *)&one);
        for (i = 0; i < 39; i++) {
            v = ls_map_lookup(m, (uint8_t *)&k);
            assert(v);
            { uint64_t nv = *v + 1; ls_map_update(m, (uint8_t *)&k, (uint8_t *)&nv); }
        }
        v = ls_map_lookup(m, (uint8_t *)&k);
        assert(v && *v == 40);   /* "this key, forty times" */                n++;
    }

    /* 7. full table EVICTS and counts --- never blocks, never fails */
    {
        uint64_t before = m->evictions;
        uint32_t k; uint64_t v = 1;
        for (k = 1000; k < 1000 + 300; k++) {
            assert(ls_map_update(m, (uint8_t *)&k, (uint8_t *)&v) == 0);
        }
        n++;
        assert(m->evictions > before);   /* loss is visible */                n++;
    }

    /* 8. THE BOUNDS CALLBACK. uBPF permits only ctx and stack; this is what
     *    extends it to map values, and the JIT does not bounds-check at all --
     *    so getting this wrong makes the interpreter and the JIT disagree. */
    {
        uint64_t base = (uint64_t)(uintptr_t)m->vals;
        assert(ls_map_addr_ok(&S, base, 8));                                 n++;
        assert(ls_map_addr_ok(&S, base + LS_MAP_VAL_MAX, 8));                n++;
        /* keys and metadata are the host's --- never legal */
        assert(!ls_map_addr_ok(&S, (uint64_t)(uintptr_t)m->keys, 4));         n++;
        assert(!ls_map_addr_ok(&S, (uint64_t)(uintptr_t)m, 4));               n++;
        /* must not straddle into the next slot */
        assert(!ls_map_addr_ok(&S, base + LS_MAP_VAL_MAX - 4, 8));           n++;
        /* nor run off the end of the array */
        assert(!ls_map_addr_ok(&S,
               base + (uint64_t)m->entries * LS_MAP_VAL_MAX - 4, 8));        n++;
        /* nor be somewhere else entirely */
        assert(!ls_map_addr_ok(&S, 0, 8));                                    n++;
        assert(!ls_map_addr_ok(&S, 0xdeadbeef, 8));                           n++;
    }

    printf("ok    ls_map.h  (%d assertions: bad descriptors refused, index "
           "validated, accumulation, evict-and-count, bounds callback)\n", n);
    return 0;
}
