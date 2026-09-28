/* Three real VMs share the host's maps. Only the output sink is substituted. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>

struct event {
    uint32_t magic, abi;
    uint64_t run, sequence, lifetime, attempt, value, failures;
    uint32_t kind, flags;
};
static struct event last;
static unsigned emissions, reject_output;
static const int slots[3] = {6, 5, 7};
static struct ubpf_vm *vms[3];
static ubpf_jit_ex_fn jits[3];
static struct ls_config_request requests[3];

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(size == sizeof last && size == 64);
    memcpy(&last, data, size);
    assert(last.magic == 0x4c494645 && last.abi == 1);
    assert(last.kind >= 1 && last.kind <= 3);
    assert(slot == slots[last.kind - 1]);
    emissions++;
    return reject_output ? -1 : 0;
}

static void call(unsigned kind, uint64_t address, uint64_t result, int mode)
{
    uint64_t ctx[12] = {address, 1, 1, 1, 1, result};
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
    assert(ret == 0 && emissions == 1 && last.kind == kind);
}

static void publish(uint64_t token)
{
    for (unsigned i = 0; i < 3; i++) {
        struct ls_config_request *r = &requests[i];
        r->expected_revision = r->revision;
        r->revision++;
        memcpy(r->rows, &token, sizeof token);
        assert(!ls_config_publish(&g_ls_config, slots[i], r, 112));
    }
}

int main(int argc, char **argv)
{
    assert(argc == 4);
    g_ls_config.session = 42;
    for (int mode = 0; mode < 2; mode++) {
        assert(!ls_map_reset_shapes());
        memset(requests, 0, sizeof requests);
        for (unsigned i = 0; i < 3; i++) {
            FILE *file = fopen(argv[i + 1], "rb");
            assert(file && !fseek(file, 0, SEEK_END));
            long length = ftell(file);
            assert(length > 0 && !fseek(file, 0, SEEK_SET));
            void *object = malloc((size_t)length);
            assert(object && fread(object, 1, (size_t)length, file) ==
                    (size_t)length);
            fclose(file);
            char *error = NULL;
            vms[i] = ubpf_create();
            struct ls_config_request *r = &requests[i];
            r->abi = r->entries = r->schema = 1;
            r->session = 42;
            r->instance = ls_config_new_instance(&g_ls_config, slots[i]);
            memset(r->program_sha256, 0xab + i, 32);
            g_ls_config.loading = r->instance;
            assert(vms[i] && !ls_map_glue_install(vms[i]));
            assert(!ubpf_load_elf_ex(vms[i], object, (size_t)length,
                    "parser_lifetime", &error));
            assert(!g_ls_config.load_error);
            jits[i] = ubpf_compile_ex(vms[i], &error, ExtendedJitMode);
            if (!jits[i]) { fprintf(stderr, "%s\n", error); return 1; }
            assert(!ls_config_bind(&g_ls_config, slots[i], r->instance,
                    r->program_sha256));
            free(object);
            call(i + 1, 1, 0, mode);
            assert(last.flags == 1 && !last.lifetime);
        }
        publish(101 + mode);
        call(2, 1, 0, mode);
        assert(last.flags == 32 && !last.lifetime);
        call(3, 1, 0, mode);
        assert(last.flags == 32 && !last.lifetime);
        call(1, 1, 0, mode);
        assert(!last.flags && last.lifetime == 1 && last.sequence == 3);
        call(2, 1, 17, mode);
        assert(!last.flags && last.attempt == 1 && last.lifetime == 1);
        call(2, 1, 17, mode);
        assert(!last.flags && last.attempt == 1);
        call(2, 1, 0, mode);
        assert(!last.flags && last.attempt == 1);
        call(2, 1, 0, mode);
        assert(!last.flags && last.attempt == 2);
        call(1, 2, 0, mode);
        call(2, 2, 17, mode);
        call(3, 2, 0, mode);
        assert(last.flags == 256 && last.lifetime == 2 && last.attempt == 1);
        call(2, 2, 0, mode);
        assert(last.flags == 64 && !last.lifetime);
        call(3, 2, 0, mode);
        assert(last.flags == 64 && !last.lifetime);
        call(3, 1, 0, mode);
        assert(!last.flags && last.attempt == 2);
        call(1, 1, 0, mode);
        assert(!last.flags && last.lifetime == 3 && last.value == 1);
        call(2, 1, 0, mode);
        assert(!last.flags && last.attempt == 1);
        call(1, 1, 0, mode);
        assert(last.flags == 128 && last.lifetime == 4 && last.value == 3);
        call(2, 1, 13, mode);
        assert(last.flags == 512);
        call(2, 1, 0, mode);
        assert(last.flags == 512);
        reject_output = 1;
        call(1, 3, 0, mode);
        assert(!last.failures);
        call(2, 3, 0, mode);
        assert(last.failures == 1);
        reject_output = 0;
        call(3, 3, 0, mode);
        assert(last.failures == 2);
        for (unsigned i = 6; i <= 256; i++) {
            call(1, 1000 + i, 0, mode);
            assert(!last.flags && last.lifetime == i);
        }
        call(1, 9999, 0, mode);
        assert(last.flags == 4 && !last.lifetime);
        call(2, 9999, 0, mode);
        assert(last.flags == 32 && !last.lifetime);
        call(1, 1, 0, mode);
        assert((last.flags & 4) && !last.lifetime);
        call(2, 1, 0, mode);
        assert(last.flags == 64 && !last.lifetime);
        call(2, 0, 0, mode);
        assert(last.flags == 16 && !last.lifetime);
        publish(201 + mode);
        call(2, 1006, 0, mode);
        assert(last.flags == 32 && !last.lifetime && last.sequence == 1);
        for (uint32_t i = 0; i < atomic_load(&g_ls_nshapes); i++) {
            if (!strcmp(g_ls_names[i], "life_state")) {
                uint32_t key = 0;
                uint64_t handle = (g_ls_maps->generation << 8) | i;
                uint64_t *state = ls_map_lookup(ls_map_get(ls_map_current(),
                        handle), (const uint8_t *)&key);
                assert(state);
                state[1] = UINT64_MAX;
            }
        }
        call(2, 1, 0, mode);
        assert(last.flags == 8 && !last.sequence);
        for (unsigned i = 0; i < 3; i++)
            ubpf_destroy(vms[i]);
        printf("PASS %s: three-program shared state; partial/completed "
                "attempts, cleanup, reuse, missing boundaries, duplicate "
                "birth/end, errors, capacity, null, output failure, "
                "run change and saturation\n", mode ? "JIT" : "interpreter");
    }
    return 0;
}
