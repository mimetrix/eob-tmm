/* Exercise both loaded maps together; single-program runs cannot prove isolation. */
#define main single_program_main
#include "check_session_routing.c"
#undef main

int main(int argc, char **argv)
{
    struct ubpf_vm *machines[2] = {0};
    ubpf_jit_ex_fn functions[2] = {0};
    assert(argc == 3 && ls_ranges_current(1));
    g_ls_config.session = 42;
    for (mode = 0; mode < 2; mode++) {
        assert(!ls_map_reset_shapes());
        for (unsigned i = 0; i < 2; i++) {
            FILE *file = fopen(argv[i + 1], "rb");
            assert(file && !fseek(file, 0, SEEK_END));
            long size = ftell(file);
            assert(size > 0 && !fseek(file, 0, SEEK_SET));
            void *obj = malloc(size);
            assert(obj && fread(obj, 1, size, file) == (size_t)size);
            fclose(file);
            struct ls_config_request request = {0};
            slot = i + 7;
            request.abi = request.schema = request.entries = 1;
            request.session = 42;
            request.instance = ls_config_new_instance(&g_ls_config, slot);
            request.revision = 1;
            memset(request.program_sha256, i + 7, 32);
            uint64_t run = 123;
            memcpy(request.rows, &run, 8);
            g_ls_config.loading = request.instance;
            char *error = NULL;
            machines[i] = ubpf_create();
            assert(machines[i] && !ls_map_glue_install(machines[i]));
            assert(!ubpf_register(machines[i], 4, "tracked_read", tracked_read));
            assert(!ubpf_load_elf_ex(machines[i], obj, size,
                        "session_routing", &error));
            functions[i] = ubpf_compile_ex(machines[i], &error, ExtendedJitMode);
            assert(functions[i]);
            assert(!ls_config_bind(&g_ls_config, slot, request.instance,
                        request.program_sha256));
            assert(!ls_config_publish(&g_ls_config, slot, &request, 112));
            free(obj);
        }
        for (unsigned sequence = 1; sequence <= 2; sequence++) {
            for (int i = 1; i >= 0; i--) {
                kind = i + 1;
                slot = i + 7;
                vm = machines[i];
                jit = functions[i];
                fixture(13);
                invoke((uintptr_t)(i ? scb : node), JM_COMPLETE,
                        i ? JM_COMPLETE : 0);
                assert(last.field.sequence == sequence);
            }
        }
        ubpf_destroy(machines[0]);
        ubpf_destroy(machines[1]);
        puts("PASS interleaved session/route map isolation");
    }
    return 0;
}
