/* Four real VMs, controlled missing invocations, and a substitute output sink. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>

struct life_event {
    uint32_t magic, abi;
    uint64_t run, sequence, lifetime, attempt, value, failures;
    uint32_t kind, flags;
};
struct candidate_event {
    uint32_t magic, abi;
    uint64_t run, sequence, lifetime, attempt, failures;
    uint32_t flags, path, total, reserved;
    char nonce[32];
};
static struct life_event life;
static struct candidate_event candidate;
static struct ubpf_vm *vms[4];
static ubpf_jit_ex_fn jits[4];
static const int slots[4] = {6, 5, 7, 8};
static const char request_a[] = "POST /mcp HTTP/1.1\r\nX-Proof-Nonce: "
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n";
static const char request_b[] = "POST /mcp HTTP/1.1\r\nX-Proof-Nonce: "
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n\r\n";
static unsigned emissions, trace, mode;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    emissions++;
    if (slot == 8) {
        assert(size == sizeof candidate);
        memcpy(&candidate, data, size);
        assert(candidate.magic == 0x43414e44 && candidate.abi == 1);
        if (candidate.flags != 1) {
            char zero[32] = {0};
            assert(!candidate.path && !memcmp(candidate.nonce, zero, 32));
        }
        if (trace)
            printf("{\"mode\":%u,\"kind\":4,\"run\":%llu,"
                "\"sequence\":%llu,\"lifetime\":%llu,\"attempt\":%llu,"
                "\"failures\":%llu,\"flags\":%u,\"path\":\"/mcp\","
                "\"nonce\":\"%.*s\"}\n", mode,
                (unsigned long long)candidate.run,
                (unsigned long long)candidate.sequence,
                (unsigned long long)candidate.lifetime,
                (unsigned long long)candidate.attempt,
                (unsigned long long)candidate.failures, candidate.flags,
                32, candidate.nonce);
    } else {
        assert(size == sizeof life);
        memcpy(&life, data, size);
        assert(life.kind >= 1 && life.kind <= 3);
        assert(slot == slots[life.kind - 1]);
        if (trace)
            printf("{\"mode\":%u,\"kind\":%u,\"run\":%llu,"
                "\"sequence\":%llu,\"lifetime\":%llu,\"attempt\":%llu,"
                "\"failures\":%llu,\"flags\":%u,\"value\":%llu}\n",
                mode, life.kind, (unsigned long long)life.run,
                (unsigned long long)life.sequence,
                (unsigned long long)life.lifetime,
                (unsigned long long)life.attempt,
                (unsigned long long)life.failures, life.flags,
                (unsigned long long)life.value);
    }
    return 0;
}

static void call(unsigned kind, uint64_t address, const char *data)
{
    uint64_t ctx[12] = {address, 0, (uintptr_t)data,
        data ? strlen(data) : 0};
    uint64_t ret = 99;
    uint8_t stack[4096] = {0};
    emissions = 0;
    g_ls_cur_slot = slots[kind - 1];
    ls_config_begin(&g_ls_config_view, g_ls_cur_slot);
    if (mode)
        ret = jits[kind - 1](ctx, sizeof ctx, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vms[kind - 1], ctx, sizeof ctx, &ret,
            stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    assert(ret == 0 && emissions == 1);
}

static void load(char **paths, uint64_t token)
{
    assert(!ls_map_reset_shapes());
    for (unsigned i = 0; i < 4; i++) {
        FILE *file = fopen(paths[i], "rb");
        long length = 0;
        void *object = NULL;
        char *error = NULL;
        struct ls_config_request r = {0};
        assert(file && !fseek(file, 0, SEEK_END));
        length = ftell(file);
        assert(length > 0 && !fseek(file, 0, SEEK_SET));
        object = malloc((size_t)length);
        assert(object && fread(object, 1, (size_t)length, file) ==
            (size_t)length);
        fclose(file);
        r.abi = r.schema = r.entries = 1;
        r.session = 42;
        r.instance = ls_config_new_instance(&g_ls_config, slots[i]);
        memset(r.program_sha256, 0xab + i, 32);
        g_ls_config.loading = r.instance;
        vms[i] = ubpf_create();
        assert(vms[i] && !ls_map_glue_install(vms[i]));
        assert(!ubpf_load_elf_ex(vms[i], object, (size_t)length,
            i == 3 ? "request_candidate" : "parser_lifetime", &error));
        assert(!g_ls_config.load_error);
        jits[i] = ubpf_compile_ex(vms[i], &error, ExtendedJitMode);
        assert(jits[i]);
        assert(!ls_config_bind(&g_ls_config, slots[i], r.instance,
            r.program_sha256));
        r.revision = 1;
        memcpy(r.rows, &token, sizeof token);
        assert(!ls_config_publish(&g_ls_config, slots[i], &r, 112));
        free(object);
    }
}

static void unload(void)
{
    for (unsigned i = 0; i < 4; i++) {
        ls_config_revoke(&g_ls_config, slots[i]);
        ubpf_destroy(vms[i]);
    }
}

int main(int argc, char **argv)
{
    assert(argc == 5);
    g_ls_config.session = 42;
    for (mode = 0; mode < 2; mode++) {
        load(argv + 1, 101 + mode);
        trace = 1;
        call(1, 1, NULL);
        call(4, 1, request_a);
        call(2, 1, NULL);
        assert(life.lifetime == 1 && life.attempt == 1);
        /* Old object ends and a new object occupies address 1. Both boundary
         * invocations are omitted. The observer cannot see that change. */
        call(4, 1, request_b);
        assert(candidate.flags == 1 && candidate.nonce[0] == 'b');
        call(2, 1, NULL);
        assert(!life.flags && life.lifetime == 1 && life.attempt == 2);
        call(3, 1, NULL);
        trace = 0;
        unload();

        load(argv + 1, 201 + mode);
        for (unsigned i = 1; i <= 256; i++) {
            call(1, i, NULL);
            assert(!life.flags && life.lifetime == i);
            call(4, i, request_a);
            assert(candidate.flags == (i <= 127 ? 1u : 256u));
            call(2, i, NULL);
            assert(!life.flags && life.lifetime == i);
            call(3, i, NULL);
            assert(!life.flags);
        }
        call(1, 257, NULL);
        assert(life.flags == 4 && !life.lifetime);
        call(4, 257, request_b);
        assert(candidate.flags == 4 && !candidate.lifetime);
        call(1, 1, NULL);
        assert(life.flags == 4 && !life.lifetime);
        call(4, 1, request_b);
        assert(candidate.flags == 4 && !candidate.path);
        unload();

        load(argv + 1, 301 + mode);
        call(4, 1, request_b);
        assert(candidate.flags == 4 && candidate.sequence == 1);
        call(2, 1, NULL);
        assert(life.flags == 32);
        call(1, 1, NULL);
        assert(!life.flags && life.lifetime == 1);
        call(4, 1, request_b);
        assert(candidate.flags == 1 && candidate.attempt == 1);
        assert(!memcmp(candidate.nonce, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 32));
        call(2, 1, NULL);
        call(3, 1, NULL);
        unload();
        printf("PASS %s: missed boundaries retain stale interval; limits "
            "127/128 and 256/257; no stale candidate after refusal; "
            "fresh reset rejects old objects and reads new marker\n",
            mode ? "JIT" : "interpreter");
    }
    return 0;
}
