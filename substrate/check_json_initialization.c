/* Exact JSON guard cases through the production VM and shadow-frame dispatch. */
#define LS_MAP_GLUE_IMPL
#include "ls_vm.c"
#include "ls_fexit.h"
#include "surfaces/json_initialization_abi.h"
#include <assert.h>
char ls_fexit_stub[1];
static struct ji_event last;
static unsigned emissions, reads, bytes, fail_read, refuse;
static struct ls_config_request request;
static _Alignas(64) unsigned char node[192], flow[64];

int ls_tp_publish_raw(int slot, const void *record, unsigned long length)
{
    assert(slot == 1 && length == sizeof last);
    memcpy(&last, record, length); emissions++;
    return refuse ? -1 : 0;
}
int ls_tp_emit_shield(int slot, unsigned gen, unsigned mode, unsigned verdict,
                      const void *ctx, unsigned long length)
{
    (void)slot; (void)gen; (void)mode; (void)verdict; (void)ctx; (void)length;
    assert(!"initialization program selected enforcement");
    return -1;
}
static uint64_t tracked_read(uint64_t dst, uint64_t n, uint64_t src,
                              uint64_t a4, uint64_t a5)
{
    reads++; bytes += n;
    if (fail_read && reads == fail_read) return 1;
    return ls_h_probe_read(dst, n, src, a4, a5);
}
static void put32(unsigned char *p, uint32_t value)
{
    memcpy(p, &value, 4);
}
static void invoke(uint64_t address, unsigned event, uint64_t uf,
                    unsigned status, unsigned action)
{
    uint64_t args[6] = {address, event, uf, 0, 0, 0};
    uint64_t return_slot = 0x12345678;
    unsigned char before[sizeof node] = {0};
    memcpy(before, node, sizeof node);
    emissions = reads = bytes = 0;
    if (action == 5) g_slots[1].armed = false;
    ls_fexit_enter(1, &return_slot, args);
    assert(emissions == 0 && !memcmp(before, node, sizeof node));
    assert(return_slot == (uintptr_t)ls_fexit_stub);
    if (action == 1) put32(node + 152, 1);
    if (action == 2) put32(node + 152, 0);
    if (action == 3) {
        request.expected_revision = request.revision++;
        assert(!ls_config_publish(&g_ls_config, 1, &request, 112));
    }
    if (action == 4) assert(!mprotect((void *)address, 4096, PROT_NONE));
    if (action == 5) g_slots[1].armed = true;
    unsigned entry_reads = reads;
    memcpy(before, node, sizeof node);
    assert(ls_fexit_leave((uintptr_t)(&return_slot + 1), UINT64_MAX) == 0x12345678);
    assert(reads == entry_reads && emissions == 1);
    assert(!memcmp(before, node, sizeof node));
    assert(last.magic == JI_MAGIC && last.status == status);
    assert(last.reads == reads && last.source_bytes == bytes);
    assert(reads <= 3 && bytes <= 9);
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++) printf("%02x", ((unsigned char *)&last)[i]);
    puts("");
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long length = ftell(file);
    assert(length > 0 && !fseek(file, 0, SEEK_SET));
    void *blob = malloc((size_t)length);
    assert(blob && fread(blob, 1, (size_t)length, file) == (size_t)length);
    assert(!fclose(file));
    assert(ls_vm_init());
    g_ls_config.session = 42;
    request.abi = request.schema = request.entries = 1;
    request.session = 42; request.revision = 1;
    request.instance = ls_config_new_instance(&g_ls_config, 1);
    memset(request.program_sha256, 1, sizeof request.program_sha256);
    request.rows[0][0] = 123;
    g_ls_config.loading = request.instance;
    assert(ls_vm_reload(1, blob, (size_t)length, "fexit/snapshot/hud_json_handler",
                        "json_initialization", LS_MODE_MONITOR) == 1);
    g_ls_config.loading = 0;
    assert(!ubpf_register(g_slots[1].vm, 4, "tracked_read", tracked_read));
    assert(!ls_config_bind(&g_ls_config, 1, request.instance, request.program_sha256));
    put32(node + 44, 0xc00060); flow[37] = 0x40;
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 6, 0);
    assert(last.flags == 2 && !reads && !last.sequence);
    assert(!ls_config_publish(&g_ls_config, 1, &request, 112));
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 1, 0);
    assert(last.guards == 3 && last.flow_side == 1 && last.sequence == 1);
    flow[37] = 0x80;
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 1, 0);
    assert(last.flow_side == 2);
    invoke((uintptr_t)node, 2, (uintptr_t)flow, 3, 0);
    assert(!reads && !last.guards);
    put32(node + 152, 1);
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 2, 2);
    assert(last.guards == 1 && reads == 2);
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 1, 1);
    put32(node + 152, 0);
    for (unsigned i = 0; i < 3; i++) {
        put32(node + 44, i == 0 ? 0x800060 : i == 1 ? 0xc0005f : 0x2c00060);
        invoke((uintptr_t)node, 57, (uintptr_t)flow, 5, 0);
    }
    put32(node + 44, 0xc00060);
    invoke(0, 57, (uintptr_t)flow, 0, 0);
    invoke((uintptr_t)node + 1, 57, (uintptr_t)flow, 5, 0);
    invoke((uintptr_t)node, 57, (uintptr_t)flow + 1, 5, 0);
    flow[37] = 0xc0;
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 5, 0);
    flow[37] = 0x40;
    for (fail_read = 1; fail_read <= 3; fail_read++)
        invoke((uintptr_t)node, 57, (uintptr_t)flow, 4, 0);
    fail_read = 0;
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(page != MAP_FAILED);
    put32((unsigned char *)page + 44, 0xc00060);
    assert(ls_ranges_current(1));
    invoke((uintptr_t)page, 57, (uintptr_t)flow, 1, 4);
    assert(ls_ranges_current(1)); /* Fixture changed its mapping permissions. */
    invoke((uintptr_t)page, 57, (uintptr_t)flow, 4, 0);
    assert(!munmap(page, 4096));
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 6, 3);
    assert(last.flags == 2);
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 0, 5);
    assert(last.flags == 1);
    refuse = 1;
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 1, 0);
    refuse = 0;
    invoke((uintptr_t)node, 57, (uintptr_t)flow, 1, 0);
    assert(last.output_failures == 1);
    assert(!g_ls_fexit_desync && !g_ls_fexit_reclaimed && !g_ls_fexit_overflow);
    assert(g_slots[1].safe_returns == 0);
    printf("PASS JSON initialization jit=%d cases=22\n", g_cfg.jit);
    ls_vm_fini(); free(blob);
    return 0;
}
