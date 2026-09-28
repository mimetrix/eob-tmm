/* Two retained TLS map sets across 100 registry replacements. */
#define LS_MAP_GLUE_IMPL
#include "ls_map_glue.h"
#include <assert.h>
#include <pthread.h>

static pthread_barrier_t barrier;
static uint64_t handle;

static void
sync_threads(void)
{
    int rc = pthread_barrier_wait(&barrier);
    assert(rc == 0 || rc == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *
reader(void *argument)
{
    uint64_t old_handle = UINT64_MAX;
    uint32_t key = 0;
    uint64_t value = (uint64_t)(uintptr_t)argument;
    for (unsigned round = 0; round < 100; round++) {
        sync_threads();
        assert(!ls_map_enter());
        struct ls_map_set *set = ls_map_current();
        struct ls_map *map = ls_map_get(set, handle);
        assert(map && !map->is_ring);
        assert(ls_map_get(set, old_handle) == NULL);
        assert(!ls_map_lookup(map, (uint8_t *)&key));
        assert(!ls_map_update(map, (uint8_t *)&key, (uint8_t *)&value));
        sync_threads(); /* Hold the reader guard while the writer tries reset. */
        sync_threads();
        assert(*(uint64_t *)ls_map_lookup(map, (uint8_t *)&key) == value);
        old_handle = handle;
        ls_map_leave();
        sync_threads();
    }
    assert(!munmap(g_ls_maps, sizeof *g_ls_maps));
    g_ls_maps = NULL;
    return NULL;
}

int
main(void)
{
    pthread_t threads[2] = {0};
    struct ls_map_def shape = {1, 4, 8, 1, 0};
    assert(!pthread_barrier_init(&barrier, NULL, 3));
    for (unsigned i = 0; i < 2; i++)
        assert(!pthread_create(&threads[i], NULL, reader, (void *)(uintptr_t)(i + 1)));
    for (unsigned round = 0; round < 100; round++) {
        assert(!ls_map_reset_shapes());
        shape.max_entries = round % 3 + 1;
        handle = ls_map_reloc(NULL, (uint8_t *)&shape, sizeof shape,
                              "thread_counter", 0, sizeof shape);
        assert(!g_ls_config.load_error);
        sync_threads();
        sync_threads();
        uint64_t generation = atomic_load(&g_ls_map_registry.generation);
        assert(ls_map_reset_shapes() == -1);
        assert(atomic_load(&g_ls_map_registry.generation) == generation);
        sync_threads();
        sync_threads();
    }
    for (unsigned i = 0; i < 2; i++) assert(!pthread_join(threads[i], NULL));
    assert(!pthread_barrier_destroy(&barrier));
    puts("PASS: 2 threads, 100 replacements; stale refs refused, fresh private values, busy reset refused");
    return 0;
}
