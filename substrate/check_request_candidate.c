/* Native extraction oracle. Real VM/read/map helpers; substituted output sink. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>

struct event {
    uint32_t magic, abi;
    uint64_t run, sequence, lifetime, attempt, failures;
    uint32_t flags, path, total, reserved;
    unsigned char nonce[32];
};
static struct event last;
static unsigned emissions, reject_output;
static struct ubpf_vm *vm;
static ubpf_jit_ex_fn jit;
static const char nonce[] = "0123456789abcdef0123456789abcdef";
static const char request[] = "POST /mcp HTTP/1.1\r\nHost: fixture\r\n"
    "X-Proof-Nonce: 0123456789abcdef0123456789abcdef\r\n\r\nBODY";

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == 8 && size == sizeof last && size == 96);
    memcpy(&last, data, size);
    assert(last.magic == 0x43414e44 && last.abi == 1);
    emissions++;
    return reject_output ? -1 : 0;
}

static void seed(uint64_t life, uint64_t attempt, uint64_t state)
{
    uint64_t key = 1, value[4] = {101, life, attempt, state};
    struct ls_map_set *set = ls_map_current();
    for (uint32_t i = 0; i < atomic_load(&g_ls_nshapes); i++) {
        if (!strcmp(g_ls_names[i], "life_objects")) {
            struct ls_map *map = ls_map_get(set, (set->generation << 8) | i);
            assert(map && !ls_map_update(map, (void *)&key, (void *)value));
            return;
        }
    }
    assert(0);
}

static void call(uint64_t address, const char *data, size_t len, int mode)
{
    uint64_t ctx[12] = {address, 1, (uintptr_t)data, len};
    uint64_t ret = 99;
    uint8_t stack[4096] = {0};
    emissions = 0;
    g_ls_cur_slot = 8;
    ls_config_begin(&g_ls_config_view, 8);
    if (mode)
        ret = jit(ctx, sizeof ctx, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    assert(ret == 0 && emissions == 1);
    if (last.flags != 1) {
        unsigned char zero[32] = {0};
        assert(!last.path && !memcmp(last.nonce, zero, 32));
    }
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long length = ftell(file);
    assert(length > 0 && !fseek(file, 0, SEEK_SET));
    void *object = malloc((size_t)length);
    assert(object && fread(object, 1, (size_t)length, file) == (size_t)length);
    fclose(file);
    g_ls_config.session = 42;
    for (int mode = 0; mode < 2; mode++) {
        assert(!ls_map_reset_shapes());
        struct ls_config_request r = {0};
        r.abi = r.schema = r.entries = 1;
        r.session = 42;
        r.instance = ls_config_new_instance(&g_ls_config, 8);
        memset(r.program_sha256, 0xab, 32);
        g_ls_config.loading = r.instance;
        vm = ubpf_create();
        assert(vm && !ls_map_glue_install(vm));
        char *error = NULL;
        assert(!ubpf_load_elf_ex(vm, object, (size_t)length, "request_candidate", &error));
        assert(!g_ls_config.load_error);
        jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
        assert(!ls_config_bind(&g_ls_config, 8, r.instance, r.program_sha256));
        call(1, request, sizeof request - 1, mode);
        assert(last.flags == 2);
        uint64_t token = 101;
        r.revision = 1;
        memcpy(r.rows, &token, 8);
        assert(!ls_config_publish(&g_ls_config, 8, &r, 112));
        call(1, request, sizeof request - 1, mode);
        assert(last.flags == 4);
        seed(1, 0, 1);
        call(1, request, sizeof request - 1, mode);
        assert(last.flags == 1 && last.path == 1 && last.lifetime == 1 && last.attempt == 1);
        assert(!memcmp(last.nonce, nonce, 32) && last.total == sizeof request - 5);
        seed(1, 1, 1);
        call(1, "POST /mcp HTTP/1.1\r\n\r\n", 22, mode);
        assert(last.flags == 512 && last.attempt == 2);
        seed(2, 1, 3);
        for (size_t i = 0; i < sizeof request - 5; i++) {
            call(1, request + i, 1, mode);
            assert(last.lifetime == 2 && last.attempt == 1);
            assert(last.flags == (i == sizeof request - 6 ? 1u : 0u));
        }
        assert(!memcmp(last.nonce, nonce, 32));
        seed(3, 0, 1);
        call(1, (void *)1, 30, mode);
        assert(last.flags == 16);
        seed(4, 0, 1);
        call(1, "HTTP/1.1 200 OK\r\n\r\n", 19, mode);
        assert(last.flags == 8);
        char duplicate[256] = {0};
        int n = snprintf(duplicate, sizeof duplicate,
                "POST /mcp HTTP/1.1\r\nX-Proof-Nonce: %s\r\nx-proof-nonce: %s\r\n\r\n", nonce, nonce);
        seed(5, 0, 1);
        call(1, duplicate, n, mode);
        assert(last.flags == 128);
        seed(6, 0, 1);
        call(1, "POST /mcp HTTP/1.1\r\nX-Proof-Nonce: z\r\n\r\n", 40, mode);
        assert(last.flags == 64);
        char bounded[1024] = {0};
        for (unsigned size = 511; size <= 513; size++) {
            n = snprintf(bounded, sizeof bounded,
                    "POST /mcp HTTP/1.1\r\nX-Proof-Nonce: %s\r\nX-Fill: ", nonce);
            memset(bounded + n, 'x', size - n - 4);
            memcpy(bounded + size - 4, "\r\n\r\n", 4);
            seed(10 + size - 511, 0, 1);
            call(1, bounded, size, mode);
            assert(last.flags == (size <= 512 ? 1u : 256u));
            assert(last.total == (size <= 512 ? size : 512));
        }
        seed(128, 0, 1);
        call(1, request, sizeof request - 1, mode);
        assert(last.flags == 256);
        seed(20, 0, 0);
        call(1, request, sizeof request - 1, mode);
        assert(last.flags == 4);
        seed(21, 0, 1);
        reject_output = 1;
        call(1, request, sizeof request - 1, mode);
        assert(last.failures == 0);
        reject_output = 0;
        seed(22, 0, 1);
        call(1, request, sizeof request - 1, mode);
        assert(last.flags == 1 && last.failures == 1);
        ubpf_destroy(vm);
        printf("PASS %s: bounded extraction, every-byte fragmentation, body exclusion, "
                "bounds 511/512/513, missing/duplicate/invalid nonce, response, "
                "read failure, output refusal, absent/ended/reused lifetime, fresh attempt\n",
                mode ? "JIT" : "interpreter");
    }
    free(object);
    return 0;
}
