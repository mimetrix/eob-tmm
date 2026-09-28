/* Two real programs share host map helpers. The output sink is a test double. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>

struct event {
    uint32_t magic, abi;
    uint64_t instance, revision, run, monotonic_ns, sequence, failures;
    uint32_t kind, code, presence, flags;
};
static struct event last;
static unsigned emissions, reject_output;
static int current_slot;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == current_slot && size == sizeof last && size == 72);
    memcpy(&last, data, size);
    assert(last.magic == 0x4d455441 && last.abi == 1);
    printf("RECORD ");
    for (size_t i = 0; i < size; i++)
        printf("%02x", ((const unsigned char *)data)[i]);
    printf("\n");
    emissions++;
    return reject_output ? -1 : 0;
}

static void invoke(struct ubpf_vm *vm, ubpf_jit_ex_fn jit, int mode,
        int slot, uint64_t code, unsigned presence)
{
    uint64_t ctx[12] = {0}, ret = 99;
    uint8_t stack[4096] = {0};
    /* Deliberately unreadable pointers, including noncanonical addresses. */
    ctx[0] = (presence & 1) ? 1 : 0;
    ctx[1] = code;
    ctx[2] = (presence & 2) ? UINT64_MAX : 0;
    ctx[3] = (presence & 4) ? 3 : 0;
    ctx[4] = 0x12345678;
    ctx[5] = 0x87654321;
    current_slot = g_ls_cur_slot = slot;
    emissions = 0;
    ls_config_begin(&g_ls_config_view, (uint32_t)slot);
    if (mode)
        ret = jit(ctx, sizeof ctx, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    assert(ret == 0 && emissions == 1);
    assert(last.code == (uint32_t)code && last.presence == presence);
    assert(last.kind == (uint32_t)(slot - 4) && last.monotonic_ns);
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    void *objects[2] = {0};
    size_t lengths[2] = {0};
    for (int i = 0; i < 2; i++) {
        FILE *file = fopen(argv[i + 1], "rb");
        assert(file && !fseek(file, 0, SEEK_END));
        long length = ftell(file);
        assert(length > 0 && !fseek(file, 0, SEEK_SET));
        lengths[i] = (size_t)length;
        objects[i] = malloc(lengths[i]);
        assert(objects[i] && fread(objects[i], 1, lengths[i], file) == lengths[i]);
        fclose(file);
    }
    g_ls_config.session = 42;
    for (int mode = 0; mode < 2; mode++) {
        struct ubpf_vm *vms[2] = {0};
        ubpf_jit_ex_fn jits[2] = {0};
        struct ls_config_request requests[2] = {0};
        char *error = NULL;
        assert(!ls_map_reset_shapes());
        for (int i = 0; i < 2; i++) {
            int slot = i + 5;
            struct ls_config_request *r = &requests[i];
            r->abi = r->schema = r->entries = 1;
            r->session = 42;
            r->instance = ls_config_new_instance(&g_ls_config, slot);
            r->revision = 1;
            memset(r->program_sha256, i + 1, 32);
            uint64_t run = 123;
            memcpy(r->rows, &run, sizeof run);
            g_ls_config.loading = r->instance;
            vms[i] = ubpf_create();
            assert(vms[i] && !ls_map_glue_install(vms[i]));
            assert(!ubpf_load_elf_ex(vms[i], objects[i], lengths[i],
                    "metadata_handler", &error));
            assert(!g_ls_config.load_error);
            jits[i] = ubpf_compile_ex(vms[i], &error, ExtendedJitMode);
            if (!jits[i]) { fprintf(stderr, "%s\n", error); return 1; }
            assert(!ls_config_bind(&g_ls_config, slot, r->instance,
                    r->program_sha256));
            invoke(vms[i], jits[i], mode, slot, 0xffffffffu, 7);
            assert(last.flags == 1 && !last.sequence);
            assert(!ls_config_publish(&g_ls_config, slot, r, 112));
        }
        assert(atomic_load(&g_ls_nshapes) == 3);
        for (int i = 0; i < 2; i++) {
            for (unsigned n = 0; n < 8; n++) {
                uint64_t code = n == 0 ? 142 : n == 1 ? UINT32_MAX :
                    0xfedcba9800000000ull | n;
                invoke(vms[i], jits[i], mode, i + 5, code, n);
                assert(!last.flags && last.sequence == n + 1);
                assert(last.instance == requests[i].instance && last.run == 123);
            }
            reject_output = 1;
            invoke(vms[i], jits[i], mode, i + 5, 0xdeadbeef, 7);
            assert(!last.failures && last.sequence == 9);
            reject_output = 0;
            invoke(vms[i], jits[i], mode, i + 5, 28, 7);
            assert(last.failures == 1 && last.sequence == 10);
        }
        for (uint32_t i = 0; i < atomic_load(&g_ls_nshapes); i++) {
            if (!strcmp(g_ls_names[i], "metadata_a2a_state")) {
                uint32_t zero = 0;
                uint64_t handle = (g_ls_maps->generation << 8) | i;
                uint64_t *state = ls_map_lookup(ls_map_get(ls_map_current(),
                        handle), (const uint8_t *)&zero);
                assert(state);
                state[1] = UINT64_MAX;
                invoke(vms[0], jits[0], mode, 5, 0xffffffffu, 0);
                assert(last.flags == 4 && !last.sequence && last.failures == 1);
                /* Simulate stale storage from a replaced loaded instance. */
                state[0] ^= 1;
                invoke(vms[0], jits[0], mode, 5, 142, 7);
                assert(!last.flags && last.sequence == 1 && !last.failures);
            }
        }
        invoke(vms[1], jits[1], mode, 6, 142, 7);
        assert(!last.flags && last.sequence == 11 && last.failures == 1);
        for (int i = 0; i < 2; i++) ubpf_destroy(vms[i]);
        printf("PASS %s: two programs, known/unknown and 32-bit codes, "
                "all argument-presence masks, unreadable pointers, no config, "
                "output refusal, saturation, stale-instance reset, isolated counts\n",
                mode ? "JIT" : "interpreter");
    }
    for (int i = 0; i < 2; i++) free(objects[i]);
    return 0;
}
