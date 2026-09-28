/* Regression for output-map -> revoke -> hash-map storage reuse.
 * Cached pre-fix executions returned 1. Corrected hosts must return zero. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>

int main(void)
{
    struct ls_map_def output = {4, 4, 4, 1, 0};
    struct ls_map_def counter = {1, 4, 32, 256, 0};
    uint32_t key = 0;
    uint64_t value[4] = {1, 2, 3, 4};
    uint64_t first = ls_map_reloc(0, (const uint8_t *)&output, sizeof output,
                                  "old_output", 0, sizeof output);
    struct ls_map_set *set = ls_map_current();
    if (!set || first != 0 || !set->m[0].is_ring)
        return 2;
    assert(!ls_map_enter());
    assert(ls_map_reset_shapes() == -1); /* No reset beneath an active call. */
    ls_map_leave();
    assert(!ls_map_reset_shapes());
    uint64_t next = ls_map_reloc(0, (const uint8_t *)&counter, sizeof counter,
                                 "new_counter", 0, sizeof counter);
    ls_map_reloc(0, (const uint8_t *)&output, sizeof output,
                 "new_output", 0, sizeof output);
    set = ls_map_current();
    struct ls_map *map = ls_map_get(set, next);
    if (!map)
        return 2;
    int result = ls_map_update(map, (const uint8_t *)&key, (const uint8_t *)value);
    printf("{\"index\":%llu,\"registered_type\":%u,\"storage_is_ring\":%u,"
           "\"update_result\":%d,\"passed\":%s}\n",
           (unsigned long long)(next & 255u), g_ls_shapes[next & 255u].type, map->is_ring,
           result, result == 0 ? "true" : "false");
    assert(ls_map_get(set, first) == NULL); /* Old VM reference cannot alias. */
    if (result == 0) {
        uint64_t *found = ls_map_lookup(map, (const uint8_t *)&key);
        assert(found && !memcmp(found, value, sizeof value));
        /* Same layout and name, new generation: no inherited values. */
        assert(!ls_map_reset_shapes());
        uint64_t replacement = ls_map_reloc(0, (const uint8_t *)&counter, sizeof counter,
                                           "new_counter", 0, sizeof counter);
        set = ls_map_current();
        assert(ls_map_get(set, next) == NULL);
        assert(!ls_map_lookup(ls_map_get(set, replacement), (const uint8_t *)&key));
        assert(ls_map_update(ls_map_get(set, replacement), (const uint8_t *)&key,
                             (const uint8_t *)value) == 0);
    }
    return result == 0 ? 0 : 1;
}
