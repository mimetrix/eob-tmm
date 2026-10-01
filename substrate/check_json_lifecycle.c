/* Three real VMs share bounded storage tags; no lifecycle is inferred. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include "surfaces/json_lifecycle_abi.h"
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
static struct jl_event last;
static unsigned emissions, reads, source_bytes, refuse, fail_read;
static int current_slot, mode;
static struct ubpf_vm *vms[3];
static ubpf_jit_ex_fn jits[3];
static _Alignas(64) unsigned char nodes[129][192], flow[64];

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == current_slot && size == sizeof last);
    memcpy(&last, data, size); emissions++;
    return refuse ? -1 : 0;
}
static uint64_t tracked_read(uint64_t dst, uint64_t n, uint64_t src,
        uint64_t a, uint64_t b)
{
    reads++; source_bytes += n;
    if (fail_read && reads == fail_read) return 1;
    return ls_h_probe_read(dst, n, src, a, b);
}
static void invoke(int kind, uint64_t node, uint64_t arg1,
        uint64_t uf, unsigned status)
{
    uint64_t ctx[12] = {node, arg1, uf}, saved[12] = {0}, ret = 99;
    uint8_t stack[4096] = {0}, before[sizeof nodes] = {0};
    memcpy(saved, ctx, sizeof ctx); memcpy(before, nodes, sizeof nodes);
    emissions = reads = source_bytes = 0;
    current_slot = g_ls_cur_slot = kind + 7;
    ls_config_begin(&g_ls_config_view, current_slot);
    if (mode) ret = jits[kind - 1](ctx, sizeof ctx, stack, sizeof stack);
    else assert(!ubpf_exec_ex(vms[kind - 1], ctx, sizeof ctx,
                &ret, stack, sizeof stack));
    g_ls_config_view.active = 0; g_ls_cur_slot = -1;
    assert(ret == 0 && emissions == 1 && last.magic == JL_MAGIC);
    assert(last.kind == (unsigned)kind && last.status == status);
    assert(last.reads == reads && last.source_bytes == source_bytes);
    assert(reads <= 4 && source_bytes <= 29);
    assert(!memcmp(ctx, saved, sizeof ctx));
    assert(!memcmp(nodes, before, sizeof nodes));
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++)
        printf("%02x", ((unsigned char *)&last)[i]);
    puts("");
}
static void call(int kind, unsigned index, uint64_t code,
        unsigned status)
{
    uint64_t node = (uintptr_t)nodes[index];
    invoke(kind, kind == 3 ? node + 64 : node,
            kind == 2 ? node + 64 : code, (uintptr_t)flow, status);
}
static void put32(unsigned char *p, uint32_t value)
{
    memcpy(p, &value, 4);
}
int main(int argc, char **argv)
{
    assert(argc == 4);
    void *objects[3] = {0}; size_t sizes[3] = {0};
    for (int i = 0; i < 3; i++) {
        FILE *f = fopen(argv[i + 1], "rb");
        assert(f && !fseek(f, 0, SEEK_END));
        long n = ftell(f); assert(n > 0 && !fseek(f, 0, SEEK_SET));
        sizes[i] = n; objects[i] = malloc(n);
        assert(objects[i] && fread(objects[i], 1, n, f) == (size_t)n);
        fclose(f);
    }
    long page = sysconf(_SC_PAGESIZE);
    void *guard = mmap(NULL, page, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED && ls_ranges_current(1));
    g_ls_config.session = 42;
    for (mode = 0; mode < 2; mode++) {
        struct ls_config_request requests[3] = {0};
        char *error = NULL;
        memset(nodes, 0, sizeof nodes); memset(flow, 0, sizeof flow);
        for (unsigned i = 0; i < 129; i++) {
            put32(nodes[i] + 44, 0xc00060);
            put32(nodes[i] + 144, 23);
            put32(nodes[i] + 152, 0x24);
            nodes[i][88] = 1;
        }
        flow[37] = 0x41;
        assert(!ls_map_reset_shapes());
        for (int i = 0; i < 3; i++) {
            struct ls_config_request *r = &requests[i];
            uint64_t run = 123;
            r->abi = r->schema = r->entries = 1; r->session = 42;
            r->instance = ls_config_new_instance(&g_ls_config, i + 8);
            r->revision = 1; memset(r->program_sha256, i + 1, 32);
            memcpy(r->rows, &run, 8); g_ls_config.loading = r->instance;
            vms[i] = ubpf_create(); assert(vms[i]);
            assert(!ls_map_glue_install(vms[i]));
            assert(!ubpf_register(vms[i], 4, "tracked_read", tracked_read));
            assert(!ubpf_load_elf_ex(vms[i], objects[i], sizes[i],
                        "json_lifecycle", &error));
            jits[i] = ubpf_compile_ex(vms[i], &error, ExtendedJitMode);
            assert(jits[i] && !ls_config_bind(&g_ls_config, i + 8,
                        r->instance, r->program_sha256));
            call(i + 1, 0, 57, 0);
            assert(last.flags == 1 && !reads && !last.sequence);
            assert(!ls_config_publish(&g_ls_config, i + 8, r, 112));
        }
        assert(atomic_load(&g_ls_nshapes) == 3);
        call(3, 1, 0, 2); assert(!last.context_tag && !last.seen_mask);
        call(1, 0, 57, 1); assert(last.context_tag == 1 && last.seen_mask == 1);
        call(2, 0, 0, 1); assert(last.seen_mask == 3 && last.flow_side == 1);
        call(3, 0, 0, 2); assert(last.seen_mask == 7 && !reads);
        call(1, 0, 5, 1); assert(last.seen_mask == 15);
        call(1, 0, 57, 1); assert(last.context_tag == 1 && last.seen_mask == 15);
        call(2, 1, 0, 1); assert(last.context_tag == 2 && last.seen_mask == 2);
        flow[37] = 0x81; call(1, 0, 1, 1); assert(last.flow_side == 2);
        put32(nodes[0] + 152, 0x25); call(1, 0, 57, 5);
        assert(last.scb_flags == 0x25); put32(nodes[0] + 152, 0x24);
        for (unsigned i = 1; i <= 4; i++) {
            fail_read = i; call(1, 0, 57, 4);
            assert(!last.context_tag && !last.flow_side && reads == i);
        }
        fail_read = 0;
        invoke(1, (uintptr_t)guard, 57, (uintptr_t)flow, 4);
        invoke(1, 0, 57, (uintptr_t)flow, 0);
        invoke(1, (uintptr_t)nodes[0], 57, 1, 3);
        invoke(2, (uintptr_t)nodes[0], 1, (uintptr_t)flow, 3);
        put32(nodes[0] + 44, 0x2c00060); call(1, 0, 57, 3);
        put32(nodes[0] + 44, 0x800060); call(1, 0, 57, 3);
        put32(nodes[0] + 44, 0xc0005f); call(1, 0, 57, 3);
        put32(nodes[0] + 44, 0xc00060);
        flow[37] = 0xc1; call(1, 0, 57, 3); flow[37] = 0x41;
        for (unsigned i = 2; i < 128; i++) {
            call(1, i, 57, 1); assert(last.context_tag == i + 1);
        }
        call(1, 128, 57, 6); assert(!last.context_tag);
        call(2, 0, 0, 1); assert(last.context_tag == 1);
        refuse = 1; call(3, 0, 0, 2); assert(!last.output_failures);
        refuse = 0; call(3, 0, 0, 2); assert(last.output_failures == 1);
        requests[0].expected_revision = 1; requests[0].revision = 2;
        uint64_t other_run = 124; memcpy(requests[0].rows, &other_run, 8);
        assert(!ls_config_publish(&g_ls_config, 8, &requests[0], 112));
        call(1, 0, 57, 9); assert(!reads && !last.context_tag);
        for (uint32_t i = 0; i < atomic_load(&g_ls_nshapes); i++) {
            if (!strcmp(g_ls_names[i], "json_boundary_state")) {
                uint32_t zero = 0;
                uint64_t handle = (g_ls_maps->generation << 8) | i;
                uint64_t *s = ls_map_lookup(ls_map_get(ls_map_current(),
                            handle), (const uint8_t *)&zero);
                assert(s); s[1] = UINT64_MAX;
                call(2, 0, 0, 7); assert(!reads && last.flags == 4);
            }
        }
        for (int i = 0; i < 3; i++) ubpf_destroy(vms[i]);
        printf("PASS %s: shared tags, late reset, reuse ambiguity, "
                "guards, capacity, refusal, run mismatch, saturation\n",
                mode ? "JIT" : "interpreter");
    }
    munmap(guard, page);
    for (int i = 0; i < 3; i++) free(objects[i]);
    return 0;
}
