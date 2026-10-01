/* Preserve all ID fixtures, then challenge the independent flow-side field. */
#include "surfaces/id_flow_abi.h"
#undef MI_MAGIC
#define MI_MAGIC IF_MAGIC
#define main id_only_main
#include "check_message_id.c"
#undef main

static void flow_call(uint64_t flow, unsigned expected, unsigned side,
        unsigned id_status)
{
    uint64_t scb[12] = {0}, ctx[12] = {0}, saved[12] = {0}, ret = 99;
    uint8_t stack[4096] = {0};
    scb[3] = (uintptr_t)&cache; scb[11] = source_flags;
    memcpy(saved, scb, sizeof scb);
    ctx[1] = (uintptr_t)scb; ctx[2] = flow;
    count = reads = bytes_read = 0;
    g_ls_cur_slot = 11; ls_config_begin(&g_ls_config_view, 11);
    if (mode) ret = jit(ctx, sizeof ctx, stack, sizeof stack);
    else assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0; g_ls_cur_slot = -1;
    assert(ret == 0 && count == 1 && last.magic == IF_MAGIC);
    assert(last.status == id_status);
    assert((last.flags >> 8) == expected && ((last.flags >> 4) & 3) == side);
    assert(last.reads == reads && last.source_bytes == bytes_read);
    assert(reads <= 80 && bytes_read <= 2048);
    assert(!memcmp(saved, scb, sizeof scb));
    assert(ctx[1] == (uintptr_t)scb && ctx[2] == flow);
    if (id_status == 1) {
        assert(last.getter_result == 1 && last.copied_length == 6);
        assert(!memcmp(last.value, "sample", 6));
    } else assert(!last.copied_length);
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++)
        printf("%02x", ((unsigned char *)&last)[i]);
    puts("");
}

int main(int argc, char **argv)
{
    assert(id_only_main(argc, argv) == 0);
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long size = ftell(file);
    assert(size > 0 && !fseek(file, 0, SEEK_SET));
    void *obj = malloc(size);
    assert(obj && fread(obj, 1, size, file) == (size_t)size);
    fclose(file);
    long page = sysconf(_SC_PAGESIZE);
    char *guard = mmap(NULL, page, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED && ls_ranges_current(1));
    for (mode = 0; mode < 2; mode++) {
        char *error = NULL;
        struct ls_config_request r = {0};
        uint64_t run = 123;
        _Alignas(64) unsigned char flow[64] = {0}, saved[64] = {0};
        assert(!ls_map_reset_shapes());
        r.abi = r.schema = r.entries = 1; r.session = 42;
        r.instance = ls_config_new_instance(&g_ls_config, 11); r.revision = 1;
        memset(r.program_sha256, 11, 32); memcpy(r.rows, &run, 8);
        g_ls_config.loading = r.instance;
        vm = ubpf_create(); assert(vm && !ls_map_glue_install(vm));
        assert(!ubpf_register(vm, 4, "tracked_read", tracked_read));
        assert(!ubpf_load_elf_ex(vm, obj, size, "message_id", &error));
        jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        assert(jit && !ls_config_bind(&g_ls_config, 11,
                    r.instance, r.program_sha256));
        fixture("{\"id\":\"sample\"}");
        flow[37] = 0x41;
        flow_call((uintptr_t)flow, 0, 0, 7);
        assert(last.flags == 1 && !reads);
        assert(!ls_config_publish(&g_ls_config, 11, &r, 112));
        const unsigned types[] = {0x41, 0x81, 0xc1, 0x01, 0x40, 0x80};
        for (unsigned i = 0; i < sizeof types / sizeof types[0]; i++) {
            flow[37] = types[i]; memcpy(saved, flow, sizeof flow);
            unsigned side = (types[i] & 0xc0) == 0x40 ? 1 :
                (types[i] & 0xc0) == 0x80 ? 2 : 0;
            flow_call((uintptr_t)flow, side ? 1 : 4, side, 1);
            assert(!memcmp(flow, saved, sizeof flow));
        }
        flow_call(0, 0, 0, 1);
        flow_call(1, 2, 0, 1);
        flow_call((uintptr_t)flow + 2, 4, 0, 1);
        flow_call((uintptr_t)guard, 3, 0, 1);
        flow_call(~0ull - 1, 4, 0, 1);
        flow[37] = 0x41; source_flags = 4;
        flow_call((uintptr_t)flow, 1, 1, 4);
        source_flags = 0x24;
        refuse = 1; flow_call((uintptr_t)flow, 1, 1, 1);
        assert(!last.output_failures);
        refuse = 0; flow_call((uintptr_t)flow, 1, 1, 1);
        assert(last.output_failures == 1);
        ubpf_destroy(vm);
        printf("PASS %s: side values, invalid storage, guarded read, "
                "ID independence, unchanged input, refusal\n",
                mode ? "JIT" : "interpreter");
    }
    munmap(guard, page); free(obj); return 0;
}
