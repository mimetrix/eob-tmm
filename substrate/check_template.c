/* Tutorial oracle. Native fixture types differ from the bytecode's views.
 * Runs real uBPF and general helpers. Only the output sink is a test double.
 * This is a bench test, not a TMM build or a traffic test.
 */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>
#include <stddef.h>

struct http_parser { uint64_t pad[3]; uint32_t header_count; };
struct http_parse_ctx {
    uint64_t pad[2];
    struct http_parser *parser;
    unsigned char pad2[7], version_num;
};
struct xbuf { uint64_t pad[2]; uint32_t len; };
static struct http_parser parser = {.header_count = 91};
static struct http_parse_ctx http = {.parser = &parser, .version_num = 1};
static struct xbuf buffer = {.len = 123};

/* Independent wire mirror; do not include the program's definitions. */
struct event {
    uint32_t magic, abi;
    uint64_t instance, revision, monotonic_ns, seen;
    uint64_t observed, threshold, result;
    uint32_t kind, flags, version, header_count, matched, verdict;
};
static struct event last;
static unsigned emissions, reject_emit;
static struct ls_config_request request;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == 5 && size == 88 && sizeof last == 88);
    memcpy(&last, data, sizeof last);
    assert(last.magic == 0x544d4d31 && last.abi == 1);
    emissions++;
    return reject_emit ? -1 : 0;
}

static void publish(uint64_t threshold, uint64_t reserved, uint64_t reset,
                    uint32_t flags, uint32_t schema)
{
    uint64_t row[4] = {threshold, reserved, reset, flags};
    request.expected_revision = g_ls_config.slots[5].current.revision;
    request.revision = request.expected_revision + 1;
    request.schema = schema;
    memcpy(request.rows[0], row, sizeof row);
    assert(!ls_config_publish(&g_ls_config, 5, &request, 112));
}

static uint64_t call(struct ubpf_vm *vm, ubpf_jit_ex_fn jit,
                     uint64_t *ctx, int native)
{
    uint64_t ret = 0;
    uint8_t stack[4096] = {0};
    emissions = 0;
    g_ls_cur_slot = 5;
    ls_config_begin(&g_ls_config_view, 5);
    if (native)
        ret = jit(ctx, 96, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vm, ctx, 96, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    return ret;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--offsets")) {
        printf("{\"http_parse_ctx\":{\"version_num\":%zu,\"parser\":%zu},"
               "\"http_parser\":{\"header_count\":%zu},"
               "\"xbuf\":{\"len\":%zu}}\n",
               offsetof(struct http_parse_ctx, version_num),
               offsetof(struct http_parse_ctx, parser),
               offsetof(struct http_parser, header_count),
               offsetof(struct xbuf, len));
        return 0;
    }
    assert(argc == 3);
    int exit_hook = !strcmp(argv[2], "exit");
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long len = ftell(file);
    assert(len > 0 && !fseek(file, 0, SEEK_SET));
    void *object = malloc((size_t)len);
    assert(object && fread(object, 1, (size_t)len, file) == (size_t)len);
    fclose(file);
    g_ls_config.session = 42;
    request.abi = request.entries = 1;
    request.session = 42;
    request.instance = ls_config_new_instance(&g_ls_config, 5);
    memset(request.program_sha256, 0xab, 32);
    struct ubpf_vm *vm = ubpf_create();
    char *error = NULL;
    assert(vm);
    g_ls_config.loading = request.instance;
    assert(!ls_map_glue_install(vm));
    assert(!ubpf_load_elf_ex(vm, object, (size_t)len, "template", &error));
    assert(!g_ls_config.load_error);
    ubpf_jit_ex_fn jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
    if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
    uint64_t ctx[12] = {(uintptr_t)&http, (uintptr_t)&buffer, 0, 0, 0, 123};
    /* Poison exit argument pointers: a valid exit observer must ignore them. */
    if (exit_hook) ctx[0] = ctx[1] = 1;
    for (int mode = 0; mode < 2; mode++) {
        assert(!ls_config_bind(&g_ls_config, 5, request.instance,
                               request.program_sha256));
        assert(call(vm, jit, ctx, mode) == 0 && emissions == 1);
        assert(last.flags == 1 && last.revision == 0);
        /* The retired schema and a nonzero reserved word must be refused. */
        publish(100, 0, (uint64_t)mode + 1, 3, 1);
        assert(call(vm, jit, ctx, mode) == 0 && last.flags == 2);
        publish(100, UINT64_MAX, (uint64_t)mode + 1, 3, 2);
        assert(call(vm, jit, ctx, mode) == 0 && last.flags == 2 && emissions == 1);
        publish(100, 0, (uint64_t)mode + 1, 3, 2);
        uint64_t want = exit_hook ? 0 : 1;
        uint64_t got = call(vm, jit, ctx, mode);
        /* A non-assert failure lets the runner test the unrelocated falsifier. */
        if (got != want || emissions != 1 || last.flags || last.observed != 123 || last.seen != 1 ||
            (!exit_hook && (last.version != 1 || last.header_count != 91))) {
            printf("MISMATCH native fields: ret=%llu emissions=%u flags=%u "
                   "observed=%llu seen=%llu version=%u headers=%u\n",
                   (unsigned long long)got, emissions, last.flags,
                   (unsigned long long)last.observed,
                   (unsigned long long)last.seen, last.version,
                   last.header_count);
            return 1;
        }
        assert(last.matched && last.monotonic_ns && last.kind == (exit_hook ? 2u : 1u));
        assert(last.result == (exit_hook ? 123u : 0u));
        publish(200, 0, (uint64_t)mode + 1, 3, 2);
        assert(call(vm, jit, ctx, mode) == 0 && last.seen == 2 && !last.matched && emissions == 1);
        /* Every rapid call must attempt output, including nonmatches. */
        for (unsigned i = 0; i < 128; i++)
            assert(call(vm, jit, ctx, mode) == 0 && emissions == 1 && last.seen == i + 3);
        publish(100, 0, 100 + (uint64_t)mode, 3, 2);
        reject_emit = 1;
        assert(call(vm, jit, ctx, mode) == want && emissions == 1 && last.seen == 1);
        assert(call(vm, jit, ctx, mode) == want && emissions == 1 && last.seen == 2);
        reject_emit = 0;
        assert(call(vm, jit, ctx, mode) == want && emissions == 1 && last.seen == 3);
        publish(100, 0, 100 + (uint64_t)mode, 0, 2);
        assert(call(vm, jit, ctx, mode) == 0 && last.flags == 32 && emissions == 1);
        publish(100, 0, 100 + (uint64_t)mode, 1, 2);
        assert(call(vm, jit, ctx, mode) == 0 && last.seen == 1 && last.matched);
        if (!exit_hook) {
            ctx[0] = 0;
            assert(call(vm, jit, ctx, mode) == 0 && last.flags == 4);
            ctx[0] = (uintptr_t)&http;
            http.parser = (void *)1;
            assert(call(vm, jit, ctx, mode) == 0 && last.flags == 4);
            http.parser = &parser;
        }
        /* A stale state entry must reset, even with the same reset token. */
        for (uint32_t i = 0; i < atomic_load(&g_ls_nshapes); i++) {
            if (!strcmp(g_ls_names[i], "tutorial_state")) {
                uint32_t key = 0;
                uint64_t *state = ls_map_lookup(ls_map_get(ls_map_current(), i),
                                                (const uint8_t *)&key);
                assert(state);
                state[0] = 0;
            }
        }
        assert(call(vm, jit, ctx, mode) == 0 && last.seen == 1);
        printf("PASS %s %s: input, revision, fields, count, reset, delete, "
               "every-call output, output refusal, verdict, stale state\n",
               mode ? "JIT" : "interpreter", argv[2]);
    }
    printf("EVENT {\"hook\":\"prog\",\"slot\":5,\"len\":88,\"data\":\"");
    for (size_t i = 0; i < sizeof last; i++)
        printf("%02x", ((const unsigned char *)&last)[i]);
    puts("\"}");
    ubpf_destroy(vm);
    free(object);
    return 0;
}
