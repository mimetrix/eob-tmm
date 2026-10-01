/* Real helper and VM execution over authored response layouts. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include "surfaces/response_metadata_abi.h"
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned char input[64];
static struct rm_event last;
static unsigned count, refused, reads, bytes;
static struct ubpf_vm *vm;
static ubpf_jit_ex_fn jit;
static int mode;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == 9 && size == sizeof last);
    memcpy(&last, data, size);
    count++;
    return refused ? -1 : 0;
}

static uint64_t tracked_read(uint64_t dst, uint64_t n, uint64_t src,
        uint64_t a, uint64_t b)
{
    reads++;
    bytes += n;
    return ls_h_probe_read(dst, n, src, a, b);
}

static void fixture(uint32_t status, unsigned flags, uint32_t invalid)
{
    memset(input, 0, sizeof input);
    input[28] = flags;
    memcpy(input + 36, &status, 4);
    memcpy(input + 40, &invalid, 4);
}

static void invoke(uint64_t code, uint64_t data, unsigned presence,
        unsigned status, unsigned done)
{
    uint64_t ctx[12] = {0}, ret = 99;
    uint8_t stack[4096] = {0}, saved[sizeof input] = {0};
    ctx[0] = presence & 1;
    ctx[1] = code;
    ctx[2] = presence & 2;
    ctx[3] = data;
    memcpy(saved, input, sizeof saved);
    count = reads = bytes = 0;
    g_ls_cur_slot = 9;
    ls_config_begin(&g_ls_config_view, 9);
    if (mode)
        ret = jit(ctx, sizeof ctx, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    assert(ret == 0 && count == 1 && !memcmp(saved, input, sizeof saved));
    assert(last.magic == RM_MAGIC && last.abi == 1 && !last.reserved);
    assert(last.code == (uint32_t)code);
    assert(last.http_status_state == status && last.completion_state == done);
    assert(last.presence == ((presence & 3) | ((data != 0) << 2)));
    assert(last.reads == reads && last.source_bytes == bytes);
    assert(reads <= 4 && bytes <= 16);
    if (status != RM_COMPLETE)
        assert(!last.http_status);
    if (done != RM_COMPLETE)
        assert(!last.transfer_complete);
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++)
        printf("%02x", ((unsigned char *)&last)[i]);
    puts("");
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long size = ftell(file);
    assert(size > 0 && !fseek(file, 0, SEEK_SET));
    void *obj = malloc(size);
    assert(obj && fread(obj, 1, size, file) == (size_t)size);
    fclose(file);
    long page = sysconf(_SC_PAGESIZE);
    char *guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED && !mprotect(guard + page, page, PROT_NONE));
    assert(ls_ranges_current(1));
    g_ls_config.session = 42;
    for (mode = 0; mode < 2; mode++) {
        char *error = NULL;
        struct ls_config_request request = {0};
        uint64_t run = 123;
        assert(!ls_map_reset_shapes());
        request.abi = request.schema = request.entries = 1;
        request.session = 42;
        request.instance = ls_config_new_instance(&g_ls_config, 9);
        request.revision = 1;
        memset(request.program_sha256, 9, 32);
        memcpy(request.rows, &run, 8);
        g_ls_config.loading = request.instance;
        vm = ubpf_create();
        assert(vm && !ls_map_glue_install(vm));
        assert(!ubpf_register(vm, 4, "tracked_read", tracked_read));
        assert(!ubpf_load_elf_ex(vm, obj, size, "response_metadata", &error));
        jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
        assert(!ls_config_bind(&g_ls_config, 9, request.instance,
                    request.program_sha256));
        fixture(200, 0, 0);
        invoke(28, (uintptr_t)input, 3, RM_UNAVAILABLE, 0);
        assert(last.flags == 1 && !reads && !last.sequence);
        assert(!ls_config_publish(&g_ls_config, 9, &request, 112));
        uint32_t statuses[] = {100, 200, 204, 404, 503, 777, 999};
        for (unsigned i = 0; i < 7; i++) {
            fixture(statuses[i], 0, 0);
            invoke(i & 1 ? 144 : 28, (uintptr_t)input, 3, RM_COMPLETE, 0);
            assert(last.http_status == statuses[i] && reads == 2 && bytes == 5);
        }
        uint32_t invalid_statuses[] = {0, 99, 1000, UINT32_MAX};
        for (unsigned i = 0; i < 4; i++) {
            fixture(invalid_statuses[i], 0, 0);
            invoke(28, (uintptr_t)input, 3, RM_OUT_OF_SCOPE, 0);
        }
        fixture(200, 1, 0);
        invoke(28, (uintptr_t)input, 3, RM_OUT_OF_SCOPE, 0);
        fixture(200, 2, 0);
        invoke(28, (uintptr_t)input, 3, RM_OUT_OF_SCOPE, 0);
        fixture(200, 0, 8);
        invoke(28, (uintptr_t)input, 3, RM_COMPLETE, 0);
        assert(last.http_status == 200);
        fixture(200, 0xfc, 0xfffffff7);
        invoke(28, (uintptr_t)input, 3, RM_COMPLETE, 0);
        assert(last.http_status == 200);
        invoke(28, 0, 3, RM_UNAVAILABLE, 0);
        invoke(28, 2, 3, RM_READ_FAILED, 0);
        invoke(28, (uintptr_t)(guard + page - 38), 3, RM_READ_FAILED, 0);
        for (unsigned presence = 0; presence < 3; presence++) {
            invoke(28, (uintptr_t)input, presence, RM_UNAVAILABLE, 0);
            assert(!reads);
        }
        for (unsigned i = 0; i < 2; i++) {
            invoke(29, i, 3, 0, RM_COMPLETE);
            assert(last.transfer_complete == i && !reads);
            invoke(145, i, 3, 0, RM_COMPLETE);
            assert(last.transfer_complete == i && !reads);
        }
        invoke(29, 2, 3, 0, RM_OUT_OF_SCOPE);
        invoke(145, UINT64_MAX, 3, 0, RM_OUT_OF_SCOPE);
        invoke(29, 1, 0, 0, RM_UNAVAILABLE);
        uint32_t others[] = {1, 5, 34, 142, 27, 143, UINT32_MAX};
        for (unsigned i = 0; i < 7; i++) {
            invoke(others[i], UINT64_MAX, 3, 0, 0);
            assert(!reads && !bytes);
        }
        refused = 1;
        invoke(29, 1, 3, 0, RM_COMPLETE);
        assert(!last.output_failures);
        refused = 0;
        invoke(29, 0, 3, 0, RM_COMPLETE);
        assert(last.output_failures == 1);
        for (uint32_t i = 0; i < atomic_load(&g_ls_nshapes); i++) {
            if (!strcmp(g_ls_names[i], "response_metadata_state")) {
                uint32_t zero = 0;
                uint64_t handle = (g_ls_maps->generation << 8) | i;
                uint64_t *state = ls_map_lookup(ls_map_get(ls_map_current(),
                            handle), (const uint8_t *)&zero);
                assert(state);
                state[1] = UINT64_MAX;
                invoke(29, 1, 3, 0, RM_COMPLETE);
                assert(last.flags == 4 && !last.sequence);
                state[0] ^= 1;
                invoke(29, 1, 3, 0, RM_COMPLETE);
                assert(!last.flags && last.sequence == 1 && !last.output_failures);
            }
        }
        ubpf_destroy(vm);
        printf("PASS %s: status, done, invalid state, guarded reads, "
                "unchanged input, refusal, saturation, replacement\n",
                mode ? "JIT" : "interpreter");
    }
    munmap(guard, page * 2);
    free(obj);
    return 0;
}
