/* Native production VM/dispatcher test. Text changes use the single-writer
 * primitive against authored functions. This is not a TMM traffic test. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_vm.c"
#include <assert.h>
#include <pthread.h>
#include <sched.h>

extern void *const ls_trampoline_table[];
static uint64_t records[4096][6];
static int record_slots[4096];
static unsigned emitted, installs, restores;
unsigned bodies;
static int restore_failure;
static _Atomic unsigned pause_output, output_paused, release_output;

int ls_tp_publish_raw(int slot, const void *record, unsigned long length)
{
    assert(emitted < 4096 && length == sizeof records[0]);
    memcpy(records[emitted], record, length);
    record_slots[emitted++] = slot;
    if (atomic_load(&pause_output)) {
        atomic_store(&output_paused, 1);
        while (!atomic_load(&release_output))
            sched_yield();
    }
    return 0;
}
int ls_tp_emit_shield(int slot, unsigned gen, unsigned mode, unsigned verdict,
                      const void *ctx, unsigned long length)
{
    (void)slot; (void)gen; (void)mode; (void)verdict; (void)ctx; (void)length;
    return 0;
}
/* No return-hook behavior is needed, but the assembly table links its stubs. */
void ls_fexit_enter(void) { abort(); }
void ls_fexit_leave(void) { abort(); }

extern uint64_t program_alpha(uint64_t a, uint64_t b);
extern uint64_t program_beta(uint64_t a, uint64_t b);
#define EXTRA(n) extern uint64_t program_extra##n(uint64_t, uint64_t);
EXTRA(0) EXTRA(1) EXTRA(2) EXTRA(3) EXTRA(4) EXTRA(5) EXTRA(6)
EXTRA(7) EXTRA(8) EXTRA(9) EXTRA(10) EXTRA(11) EXTRA(12) EXTRA(13)
#undef EXTRA
static uint64_t (*const targets[])(uint64_t, uint64_t) = {
    program_alpha, program_beta, program_extra0, program_extra1,
    program_extra2, program_extra3, program_extra4, program_extra5,
    program_extra6, program_extra7, program_extra8, program_extra9,
    program_extra10, program_extra11, program_extra12, program_extra13
};

static void *in_flight(void *unused)
{
    (void)unused;
    assert(ls_vm_init());
    assert(program_alpha(40, 2) == 42);
    free(g_prog_stack);
    for (unsigned id = 0; id < LS_MAP_NAMESPACES; id++)
        if (g_ls_map_namespaces[id].maps)
            assert(!munmap(g_ls_map_namespaces[id].maps, sizeof(struct ls_map_set)));
    return NULL;
}

static int patch(uint64_t address, unsigned site, int install)
{
    if (!install && restore_failure)
        return -1;
    int rc = install ? ls_arm((void *)(uintptr_t)address, ls_trampoline_table[site]) :
                       ls_disarm((void *)(uintptr_t)address);
    if (!rc) {
        if (install) installs++;
        else restores++;
    }
    return rc;
}

static const uint8_t sha[32] = {1};
static uint64_t configure(unsigned id, uint64_t label)
{
    struct ls_program_status status;
    assert(!ls_program_status(id, &status) && status.instance);
    struct ls_config_request request = {0};
    request.abi = LS_CONFIG_ABI;
    request.schema = 1;
    request.session = g_ls_config.session;
    request.instance = status.instance;
    request.revision = 1;
    request.entries = 1;
    memcpy(request.program_sha256, sha, sizeof sha);
    memcpy(request.rows, &label, sizeof label);
    assert(!ls_config_publish(&g_ls_config, status.config_slot, &request,
                              LS_CONFIG_REQUEST_HEADER + LS_CONFIG_VALUE_SIZE));
    return status.instance;
}

static void expect(unsigned at, uint64_t instance, uint64_t count,
                    uint64_t arg, uint64_t entry, uint64_t label)
{
    assert(at < emitted);
    assert(records[at][0] == instance && records[at][1] == count);
    assert(records[at][2] == arg && records[at][3] == 0);
    assert(records[at][4] == entry && records[at][5] == label);
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    assert(!setenv("LS_VM_JIT", argv[2], 1));
    assert(!setenv("LS_VM_SELFTEST", "0", 1));
    assert(!setenv("LS_VM_BENCH", "0", 1));
    assert(ls_vm_init());
    g_ls_config.session = 1;
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long length = ftell(file);
    assert(length > 0 && !fseek(file, 0, SEEK_SET));
    void *elf = malloc((size_t)length);
    assert(elf && fread(elf, 1, (size_t)length, file) == (size_t)length);
    fclose(file);
    struct ls_program_entry entries[2] = {
        {"fentry/program_alpha", (uint64_t)(uintptr_t)program_alpha, 4},
        {"fentry/program_beta", (uint64_t)(uintptr_t)program_beta, 4}
    };
    unsigned char original[2][9];
    memcpy(original[0], (void *)program_alpha, 9);
    memcpy(original[1], (void *)program_beta, 9);
    assert(!memcmp(original[0], "\xf3\x0f\x1e\xfa\x90\x90\x90\x90\x90", 9));
    assert(!ls_program_load(0, elf, (size_t)length, entries, 2, sha, LS_MODE_ENFORCE));
    assert(!ls_program_load(1, elf, (size_t)length, entries, 2, sha, LS_MODE_MONITOR));
    uint64_t first = configure(0, 100), second = configure(1, 200);
    assert(first != second);
    assert(ls_program_load(0, elf, (size_t)length, entries, 2, sha, 1) < 0);
    for (unsigned id = 0; id < 2; id++) {
        uint64_t instance = id ? second : first;
        for (unsigned i = 0; i < 2; i++)
            assert(!ls_program_attach(id, instance, i, patch));
        assert(!ls_program_mode(id, instance, LS_MODE_MONITOR));
    }
    assert(installs == 2);
    assert(!setenv("LS_SHIELD_SAFE_VALUE", "7", 1));
    assert(!ls_program_load(2, elf, (size_t)length, entries, 2, sha, 1));
    uint64_t conflict = configure(2, 300);
    assert(ls_program_attach(2, conflict, 0, patch) < 0);
    assert(!ls_program_revoke(2, conflict, patch));
    assert(!unsetenv("LS_SHIELD_SAFE_VALUE"));
    assert(ls_program_attach(0, first, 0, patch) < 0);
    assert(ls_program_detach(0, second, 0, patch) < 0);
    assert(ls_program_mode(1, second, LS_MODE_ENFORCE) < 0);
    assert(program_alpha(40, 2) == 42 && program_beta(40, 2) == 52);
    assert(emitted == 4 && bodies == 2);
    expect(0, first, 1, 40, 0, 100); expect(1, second, 1, 40, 0, 200);
    expect(2, first, 2, 40, 1, 100); expect(3, second, 2, 40, 1, 200);
    assert(record_slots[0] != record_slots[1] && record_slots[0] != record_slots[2]);
    assert(!ls_program_mode(0, first, LS_MODE_ENFORCE));
    assert(program_alpha(40, 1) == 0 && emitted == 6 && bodies == 2);
    expect(4, first, 3, 40, 0, 100); expect(5, second, 3, 40, 0, 200);
    puts("PASS two programs/two hooks; shared state within owner; isolated names/config/context; verdict composition");

    pthread_t thread;
    atomic_store(&pause_output, 1);
    assert(!pthread_create(&thread, NULL, in_flight, NULL));
    while (!atomic_load(&output_paused))
        sched_yield();
    assert(ls_program_revoke(0, first, patch) < 0);
    atomic_store(&release_output, 1);
    assert(!pthread_join(thread, NULL));
    atomic_store(&pause_output, 0);
    puts("PASS real in-flight VM call prevents reclamation; per-thread stacks/maps");

    unsigned before = emitted;
    struct ls_ctx_generic input = {{40, 2}, {0}};
    struct ls_tramp_result output;
    int site = g_programs.programs[0].sites[0];
    assert(ls_program_dispatch((unsigned)site, 123, &input, &output));
    assert(output.verdict == LS_FALLTHROUGH && emitted == before);
    assert(!ls_program_detach(0, first, 0, patch));
    assert(restores == 0 && program_alpha(40, 2) == 42);
    expect(before, second, 4, 40, 0, 200);
    assert(!ls_program_revoke(0, first, patch));
    assert(restores == 0 && program_beta(40, 2) == 52);
    expect(before + 1, second, 5, 40, 1, 200);
    restore_failure = 1;
    assert(ls_program_revoke(1, second, patch) < 0);
    assert(g_programs.programs[1].instance == second && !g_programs.programs[1].mode);
    restore_failure = 0;
    assert(!ls_program_revoke(1, second, patch) && restores == 2);
    assert(!memcmp(original[0], (void *)program_alpha, 9));
    assert(!memcmp(original[1], (void *)program_beta, 9));
    puts("PASS detach/revoke preserves other owner; restore failure retained for retry; in-flight reclamation refused");

    strcpy(entries[1].section, "fentry/missing");
    assert(ls_program_load(0, elf, (size_t)length, entries, 2, sha, 1) < 0);
    assert(!g_programs.programs[0].instance);
    for (unsigned i = 0; i < LS_PROGRAM_ENTRIES; i++)
        assert(!g_slots[ls_program_slot(0, i)].vm);
    strcpy(entries[1].section, "fentry/program_beta");
    struct ls_map_set *storage = g_ls_map_namespaces[0].maps;
    uint64_t stale_map = storage->generation << 8;
    for (unsigned cycle = 0; cycle < 32; cycle++) {
        assert(!ls_program_load(0, elf, (size_t)length, entries, 2, sha, 1));
        uint64_t fresh = configure(0, 300);
        assert(fresh != first && ls_program_mode(0, first, 1) < 0);
        assert(!ls_program_attach(0, fresh, 0, patch));
        assert(!ls_program_mode(0, fresh, 1));
        before = emitted;
        assert(program_alpha(5, 2) == 7);
        expect(before, fresh, 1, 5, 0, 300);
        assert(g_ls_map_namespaces[0].maps == storage);
        assert(!ls_map_get(storage, stale_map));
        assert(!ls_program_revoke(0, fresh, patch));
    }
    for (unsigned id = 0; id < LS_PROGRAM_MAX; id++) {
        entries[0].address = (uint64_t)(uintptr_t)targets[2 * id];
        entries[1].address = (uint64_t)(uintptr_t)targets[2 * id + 1];
        assert(!ls_program_load(id, elf, (size_t)length, entries, 2, sha, 1));
        uint64_t fresh = configure(id, id);
        assert(!ls_program_mode(id, fresh, 1));
        for (unsigned i = 0; i < 2; i++) {
            int attached = ls_program_attach(id, fresh, i, patch);
            assert(id < 6 ? attached == 0 : attached < 0);
        }
    }
    assert(ls_program_load(LS_PROGRAM_MAX, elf, (size_t)length, entries, 2, sha, 1) < 0);
    before = emitted;
    for (unsigned i = 0; i < 12; i++) {
        (void)targets[i](42, 2);
        assert(emitted == before + i + 1);
    }
    for (unsigned id = 0; id < LS_PROGRAM_MAX; id++)
        assert(!ls_program_revoke(id, g_programs.programs[id].instance, patch));
    assert(installs == restores);
    puts("PASS failed multi-entry load rollback; 32 load/revoke cycles; map bank reuse; stale map/control refusal; eight-program/twelve-site capacity");
    free(elf);
    ls_vm_fini();
    free(g_prog_stack);
    for (unsigned id = 0; id < LS_MAP_NAMESPACES; id++)
        if (g_ls_map_namespaces[id].maps)
            assert(!munmap(g_ls_map_namespaces[id].maps, sizeof(struct ls_map_set)));
    return 0;
}
