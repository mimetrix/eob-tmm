/* Real interpreter/JIT and map helpers; output uses a test sink. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>

struct event {
    uint32_t magic, abi;
    uint64_t instance, call_seq, context_tag, completions, result;
    uint64_t output_failures;
    uint32_t flags, reserved;
};
static struct event last;
static unsigned emissions, reject_emit;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == 5 && size == 64 && sizeof last == 64);
    memcpy(&last, data, sizeof last);
    assert(last.magic == 0x53434f50 && last.abi == 1);
    assert(!last.reserved);
    emissions++;
    return reject_emit ? -1 : 0;
}

static void call(struct ubpf_vm *vm, ubpf_jit_ex_fn jit,
        uint64_t address, uint64_t result, int mode)
{
    uint64_t ctx[12] = {address, 1, 1, 1, 1, result};
    uint64_t ret = 99;
    uint8_t stack[4096] = {0};
    emissions = 0;
    g_ls_cur_slot = 5;
    ls_config_begin(&g_ls_config_view, 5);
    if (mode)
        ret = jit(ctx, 96, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vm, ctx, 96, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    assert(ret == 0 && emissions == 1 && last.result == result);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long len = ftell(file);
    assert(len > 0 && !fseek(file, 0, SEEK_SET));
    void *object = malloc((size_t)len);
    assert(object && fread(object, 1, (size_t)len, file) == (size_t)len);
    fclose(file);
    g_ls_config.session = 42;
    for (int mode = 0; mode < 2; mode++) {
        struct ls_config_request request = {0};
        request.abi = request.entries = request.schema = 1;
        request.session = 42;
        request.instance = ls_config_new_instance(&g_ls_config, 5);
        request.revision = 1;
        memset(request.program_sha256, 0xab, 32);
        struct ubpf_vm *vm = ubpf_create();
        char *error = NULL;
        assert(vm && !ls_map_reset_shapes());
        g_ls_config.loading = request.instance;
        assert(!ls_map_glue_install(vm));
        assert(!ubpf_load_elf_ex(vm, object, (size_t)len,
                "request_scope", &error));
        assert(!g_ls_config.load_error);
        ubpf_jit_ex_fn jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
        assert(!ls_config_bind(&g_ls_config, 5, request.instance,
                request.program_sha256));
        call(vm, jit, 1, 13, mode);
        assert(last.flags == 1 && !last.instance && !last.call_seq);
        assert(!ls_config_publish(&g_ls_config, 5, &request, 112));
        /* Address 1 is deliberately unreadable; the program must not read it. */
        call(vm, jit, 1, 13, mode);
        assert(!last.flags && last.call_seq == 1);
        assert(last.context_tag == 1 && last.completions == 0);
        call(vm, jit, 1, 0, mode);
        assert(!last.flags && last.call_seq == 2);
        assert(last.context_tag == 1 && last.completions == 1);
        /* Reusing an address keeps its tag. It is NOT a new-lifetime detector. */
        call(vm, jit, 1, 0, mode);
        assert(!last.flags && last.completions == 2);
        for (unsigned i = 2; i <= 256; i++) {
            call(vm, jit, i, 13, mode);
            assert(!last.flags && last.context_tag == i);
            assert(!last.completions);
        }
        call(vm, jit, 257, 0, mode);
        assert(last.flags == 4 && !last.context_tag);
        call(vm, jit, 1, 13, mode);
        assert(!last.flags && last.context_tag == 1);
        assert(last.completions == 2);
        call(vm, jit, 0, 0, mode);
        assert(last.flags == 16 && !last.context_tag);
        reject_emit = 1;
        call(vm, jit, 1, 13, mode);
        assert(!last.output_failures);
        call(vm, jit, 1, 13, mode);
        assert(last.output_failures == 1);
        reject_emit = 0;
        call(vm, jit, 1, 13, mode);
        assert(last.output_failures == 2 && !last.flags);
        for (uint32_t i = 0; i < atomic_load(&g_ls_nshapes); i++) {
            if (!strcmp(g_ls_names[i], "scope_state")) {
                uint32_t key = 0;
                uint64_t handle = (g_ls_maps->generation << 8) | i;
                uint64_t *state = ls_map_lookup(ls_map_get(ls_map_current(),
                        handle), (const uint8_t *)&key);
                assert(state);
                state[1] = UINT64_MAX;
            }
        }
        call(vm, jit, 1, 0, mode);
        assert(last.flags == 8 && !last.call_seq);
        printf("PASS %s: unsampled calls, partial/completed headers, "
                "opaque address reuse, capacity refusal without eviction, "
                "null address, output refusals, saturated count\n",
                mode ? "JIT" : "interpreter");
        ubpf_destroy(vm);
    }
    free(object);
    return 0;
}
