/* P21 host concurrency and actual uBPF interpreter/JIT integration tests. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static struct ls_config_request request;
static unsigned emissions, publish_on_emit;
static uint64_t event_revision, event_threshold;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    struct { uint64_t revision, instance, observation, threshold; uint32_t matched, schema; } e;
    assert(slot == 5 && size == sizeof e);
    memcpy(&e, data, sizeof e);
    assert(e.observation == 123 && e.schema == 1);
    assert(e.matched == (123 >= e.threshold));
    emissions++;
    event_revision = e.revision;
    event_threshold = e.threshold;
    if (publish_on_emit) {
        publish_on_emit = 0;
        assert(!ls_config_publish(&g_ls_config, 5, &request, 112));
    }
    return 0;
}

static void policy(uint64_t expected, uint64_t revision, uint64_t threshold)
{
    request.expected_revision = expected;
    request.revision = revision;
    memset(request.rows, 0, sizeof request.rows);
    memcpy(request.rows[0], &threshold, 8);
    request.rows[0][8] = 1;
}

static void refusals(void)
{
    struct ls_config_request bad;
    const struct ls_config_meta before = g_ls_config.slots[5].current;
#define BAD(change, length) do { bad = request; change; \
    assert(ls_config_publish(&g_ls_config, 5, &bad, length)); \
    assert(!memcmp(&before, &g_ls_config.slots[5].current, sizeof before)); } while (0)
    BAD(bad.session++, 112);
    BAD(bad.instance++, 112);
    BAD(bad.program_sha256[0]++, 112);
    BAD(bad.expected_revision++, 112);
    BAD(bad.revision = bad.expected_revision, 112);
    BAD(bad.abi++, 112);
    BAD(bad.schema = 0, 112);
    BAD(bad.reserved = 1, 112);
    BAD(bad.entries = 17, 112);
    BAD(bad.entries = 2, 112);
    BAD((void)0, 111);
    BAD((void)0, 113);
    BAD((void)0, 79);
    assert(ls_config_publish(&g_ls_config, 64, &request, 112));
    assert(ls_config_publish(&g_ls_config, 4, &request, 112));
#undef BAD
    puts("PASS stale identities/revisions, malformed requests, cross-slot publication");
}

static _Atomic unsigned stop_readers, good_reads, unavailable;
static void *reader(void *unused)
{
    (void)unused;
    struct ls_config_view view = {0};
    while (!atomic_load(&stop_readers)) {
        ls_config_begin(&view, 5);
        struct ls_config_meta *m = ls_config_lookup(&g_ls_config, &view, request.instance, 0);
        if (!m) { atomic_fetch_add(&unavailable, 1); continue; }
        uint64_t revision = m->revision;
        assert(m->entries == 16);
        for (unsigned k = 1; k <= 16; k++) {
            uint64_t *row = ls_config_lookup(&g_ls_config, &view, request.instance, k);
            assert(row);
            for (unsigned w = 0; w < 4; w++) assert(row[w] == revision);
        }
        assert(((struct ls_config_meta *)ls_config_lookup(
            &g_ls_config, &view, request.instance, 0))->revision == revision);
        atomic_fetch_add(&good_reads, 1);
    }
    return NULL;
}

static void stress(void)
{
    struct ls_config_request r = request;
    r.entries = 16;
    r.expected_revision = g_ls_config.slots[5].current.revision;
    pthread_t threads[4];
    for (unsigned n = 0; n < 10001; n++) {
        r.revision = r.expected_revision + 1;
        for (unsigned k = 0; k < 16; k++)
            for (unsigned w = 0; w < 4; w++) memcpy(r.rows[k] + w * 8, &r.revision, 8);
        assert(!ls_config_publish(&g_ls_config, 5, &r, sizeof r));
        r.expected_revision = r.revision;
        if (n == 0) for (unsigned t = 0; t < 4; t++) assert(!pthread_create(&threads[t], NULL, reader, NULL));
    }
    atomic_store(&stop_readers, 1);
    for (unsigned t = 0; t < 4; t++) assert(!pthread_join(threads[t], NULL));
    assert(atomic_load(&good_reads));
    printf("PASS 10000 concurrent updates / four readers: coherent=%u unavailable=%u\n",
           atomic_load(&good_reads), atomic_load(&unavailable));
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    g_ls_config.session = 0x123456789;
    request.abi = 1;
    request.schema = 1;
    request.entries = 1;
    request.session = g_ls_config.session;
    request.instance = ls_config_new_instance(&g_ls_config, 5);
    memset(request.program_sha256, 0xab, 32);
    assert(!ls_config_bind(&g_ls_config, 5, request.instance, request.program_sha256));
    policy(0, 1, 100);
    refusals();

    FILE *f = fopen(argv[1], "rb");
    assert(f && !fseek(f, 0, SEEK_END));
    long len = ftell(f);
    assert(len > 0 && !fseek(f, 0, SEEK_SET));
    void *object = malloc((size_t)len);
    assert(object && fread(object, 1, (size_t)len, f) == (size_t)len);
    fclose(f);
    struct ubpf_vm *vm = ubpf_create();
    char *error = NULL;
    assert(vm);
    g_ls_config.loading = request.instance;
    assert(!ls_map_glue_install(vm));
    assert(!ubpf_load_elf_ex(vm, object, (size_t)len, "config_threshold", &error));
    assert(!g_ls_config.load_error);
    g_ls_config.loading = 0;
    ubpf_jit_ex_fn jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
    if (!jit) { fprintf(stderr, "JIT: %s\n", error); return 1; }
    uint64_t ctx[12] = {123}, ret;
    uint8_t stack[4096] = {0};
    for (unsigned j = 0; j < 2; j++) {
        for (unsigned call = 0; call < 3; call++) {
            if (call == 1) {
                policy(g_ls_config.slots[5].current.revision,
                       g_ls_config.slots[5].current.revision + 1, 100);
                assert(!ls_config_publish(&g_ls_config, 5, &request, 112));
                uint64_t old_revision = request.revision;
                policy(old_revision, old_revision + 1, 200);
                publish_on_emit = 1;
            }
            emissions = 0;
            g_ls_cur_slot = 5;
            ls_config_begin(&g_ls_config_view, 5);
            if (j) ret = jit(ctx, sizeof ctx, stack, sizeof stack);
            else assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
            assert(ret == 0);
            if (call == 0) assert(!emissions);
            else {
                assert(emissions == 1);
                assert(event_threshold == (call == 1 ? 100u : 200u));
                assert(event_revision == request.revision - (call == 1));
            }
            g_ls_config_view.active = 0;
            g_ls_cur_slot = -1;
        }
        /* Reset binding between execution modes; code's original token remains. */
        assert(!ls_config_bind(&g_ls_config, 5, request.instance, request.program_sha256));
        printf("PASS %s: no-input, publish during emit, invocation consistency, next revision\n",
               j ? "JIT" : "interpreter");
    }
    policy(0, 1, 100);
    assert(!ls_config_publish(&g_ls_config, 5, &request, 112));
    /* A reader that overlaps a writer declines for the WHOLE invocation, even
     * when the writer finishes before its next lookup. No implicit retry. */
    uint64_t seq = atomic_load(&g_ls_config.slots[5].sequence);
    atomic_store(&g_ls_config.slots[5].sequence, seq + 1);
    ls_config_begin(&g_ls_config_view, 5);
    assert(!ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 0));
    atomic_store(&g_ls_config.slots[5].sequence, seq + 2);
    assert(!ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 0));
    puts("PASS concurrent-writer unavailability stays unavailable for the whole invocation");
    ls_config_begin(&g_ls_config_view, 5);
    uint64_t *row = ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 1);
    assert(row && row[0] == 100);
    row[0] = 999; /* verifier permissions are not the host-image protection */
    assert(ls_config_addr_ok(&g_ls_config_view, (uintptr_t)row, 32));
    assert(!ls_config_addr_ok(&g_ls_config_view, (uintptr_t)row + 31, 2));
    uint32_t key = 1;
    assert(ls_h_map_update(request.instance, (uintptr_t)&key, (uintptr_t)row, 0, 0) == UINT64_MAX);
    assert(ls_h_map_delete(request.instance, (uintptr_t)&key, 0, 0, 0) == UINT64_MAX);
    ls_config_begin(&g_ls_config_view, 5);
    row = ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 1);
    assert(row && row[0] == 100);
    assert(!ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 17));
    g_ls_config_view.active = 0;
    assert(!ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 1));
    puts("PASS stores isolated to invocation copy; update/delete/out-of-bounds/inactive refused");
    /* An explicit empty snapshot withdraws all rows without resetting identity
     * or revision, and cannot expose bytes left over from the earlier image. */
    policy(1, 2, 200);
    request.entries = 0;
    assert(!ls_config_publish(&g_ls_config, 5, &request, LS_CONFIG_REQUEST_HEADER));
    ls_config_begin(&g_ls_config_view, 5);
    assert(ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 0));
    assert(!ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 1));
    for (size_t i = 0; i < sizeof g_ls_config_view.image.rows; i++)
        assert(((uint8_t *)g_ls_config_view.image.rows)[i] == 0);
    request.entries = 1;
    puts("PASS empty snapshot advances revision and clears previous data");
    stress();
    uint64_t newer = ls_config_new_instance(&g_ls_config, 5);
    assert(!ls_config_bind(&g_ls_config, 5, newer, request.program_sha256));
    ls_config_begin(&g_ls_config_view, 5);
    assert(!ls_config_lookup(&g_ls_config, &g_ls_config_view, request.instance, 0));
    assert(ls_config_publish(&g_ls_config, 5, &request, 112));
    assert(!ls_config_revoke(&g_ls_config, 5));
    assert(!g_ls_config.slots[5].current.instance);
    struct ls_map_def wrong = {2, 4, 32, 17, 0};
    g_ls_config.load_error = 0;
    ls_map_reloc((void *)(uintptr_t)newer, (void *)&wrong, sizeof wrong,
                 LS_CONFIG_MAP_NAME, 0, sizeof wrong);
    assert(g_ls_config.load_error);
    puts("PASS replacement/revoke invalidate old token; invalid ARRAY declaration refused");
    ubpf_destroy(vm);
    free(object);
    return 0;
}
