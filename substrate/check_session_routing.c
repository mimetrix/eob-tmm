/* Real VM/helper execution over authored, byte-exact layout fixtures. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include "surfaces/session_routing_abi.h"
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned char node[160], scb[88], client[200], peer[200];
static unsigned char member[160], pool[40], text[80];
static struct sr_event last;
static unsigned count, refused, reads, bytes, slot, kind;
static struct ubpf_vm *vm;
static ubpf_jit_ex_fn jit;
static int mode;

int ls_tp_publish_raw(int output_slot, const void *data, unsigned long size)
{
    assert(output_slot == (int)slot && size == sizeof last);
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

static void word(void *base, unsigned offset, uint64_t value)
{
    memcpy((char *)base + offset, &value, 8);
}

static void fixture(unsigned length)
{
    memset(node, 0, sizeof node);
    memset(scb, 0, sizeof scb);
    memset(client, 0, sizeof client);
    memset(peer, 0, sizeof peer);
    memset(member, 0, sizeof member);
    memset(pool, 0, sizeof pool);
    memset(text, 0, sizeof text);
    memset(text, 's', length);
    word(node, 44, 0xc00058);
    word(node, 128, (uintptr_t)text);
    word(node, 136, length);
    word(scb, 80, (uintptr_t)client);
    word(client, 72, (uintptr_t)peer);
    word(peer, 184, (uintptr_t)member);
    word(member, 0, (uintptr_t)pool);
    word(pool, 32, (uintptr_t)text);
    member[146] = member[147] = 0xff;
    member[148] = 10;
    member[149] = 203;
    member[150] = 76;
    member[151] = 11;
    member[152] = 0xaf;
    member[153] = 0x46;
    member[154] = 7;
}

static void invoke(uint64_t pointer, unsigned status, unsigned endpoint)
{
    uint64_t ctx[12] = {pointer, 1}, ret = 99;
    uint8_t stack[4096] = {0};
    unsigned char saved[1028] = {0};
    void *sources[] = {node, scb, client, peer, member, pool, text};
    size_t sizes[] = {sizeof node, sizeof scb, sizeof client, sizeof peer,
        sizeof member, sizeof pool, sizeof text};
    size_t offset = 0;
    assert(sizeof last == 168);
    for (unsigned i = 0; i < 7; i++) {
        assert(offset + sizes[i] <= sizeof saved);
        memcpy(saved + offset, sources[i], sizes[i]);
        offset += sizes[i];
    }
    count = reads = bytes = 0;
    g_ls_cur_slot = slot;
    ls_config_begin(&g_ls_config_view, slot);
    if (mode)
        ret = jit(ctx, sizeof ctx, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    if (last.field.status != status || last.endpoint_status != endpoint)
        fprintf(stderr, "expected %u/%u got %u/%u\n", status, endpoint,
                last.field.status, last.endpoint_status);
    assert(ret == 0 && count == 1 && last.field.status == status);
    assert(last.endpoint_status == endpoint);
    assert(last.field.magic == SR_MAGIC && last.field.getter_result == kind);
    assert(last.field.reads == reads && last.field.source_bytes == bytes);
    assert(reads <= 80 && bytes <= 256);
    offset = 0;
    for (unsigned i = 0; i < 7; i++) {
        assert(!memcmp(saved + offset, sources[i], sizes[i]));
        offset += sizes[i];
    }
    if (status != JM_COMPLETE && status != JM_TRUNCATED)
        assert(!last.field.copied_length);
    for (unsigned i = last.field.copied_length; i < 64; i++)
        assert(!last.field.value[i]);
    if (endpoint != JM_COMPLETE) {
        for (unsigned i = 0; i < 16; i++)
            assert(!last.address[i]);
        assert(!last.port && !last.domain);
    }
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++)
        printf("%02x", ((unsigned char *)&last)[i]);
    puts("");
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    kind = atoi(argv[2]);
    assert(kind == 1 || kind == 2);
    slot = kind == 1 ? 7 : 8;
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
        assert(!ls_map_reset_shapes());
        struct ls_config_request request = {0};
        request.abi = request.schema = request.entries = 1;
        request.session = 42;
        request.instance = ls_config_new_instance(&g_ls_config, slot);
        request.revision = 1;
        memset(request.program_sha256, 7, 32);
        uint64_t run = 123;
        memcpy(request.rows, &run, 8);
        g_ls_config.loading = request.instance;
        vm = ubpf_create();
        assert(vm && !ls_map_glue_install(vm));
        assert(!ubpf_register(vm, 4, "tracked_read", tracked_read));
        assert(!ubpf_load_elf_ex(vm, obj, size, "session_routing", &error));
        jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
        assert(!ls_config_bind(&g_ls_config, slot, request.instance,
                    request.program_sha256));
        uint64_t pointer = (uintptr_t)(kind == 1 ? node : scb);
        unsigned endpoint = kind == 1 ? 0 : JM_COMPLETE;
        invoke(pointer, JM_UNAVAILABLE, kind == 1 ? 0 : JM_UNAVAILABLE);
        assert(last.field.flags == 1 && !reads);
        assert(!ls_config_publish(&g_ls_config, slot, &request, 112));
        unsigned lengths[] = {0, 1, 13, 63, 64, 65};
        for (unsigned i = 0; i < 6; i++) {
            unsigned n = lengths[i];
            fixture(n);
            invoke(pointer, n > 64 ? JM_TRUNCATED : JM_COMPLETE, endpoint);
            assert(last.field.copied_length == (n > 64 ? 64 : n));
            assert(last.field.original_length ==
                    ((kind == 2 && n > 64) ? 0xffffffffu : n));
            assert(!memcmp(last.field.value, text, last.field.copied_length));
            if (kind == 2) {
                assert(!memcmp(last.address, member + 136, 16));
                assert(last.port == 18095 && last.domain == 7);
            }
        }
        fixture(13);
        if (kind == 1) {
            word(node, 44, 88); invoke(pointer, JM_OUT_OF_SCOPE, 0);
            word(node, 44, 0xc00008); invoke(pointer, JM_OUT_OF_SCOPE, 0);
            fixture(13); word(node, 128, 0); invoke(pointer, JM_UNAVAILABLE, 0);
            fixture(13); word(node, 128, 1); invoke(pointer, JM_READ_FAILED, 0);
            fixture(13); word(node, 136, 0x100000000ull); invoke(pointer, JM_UNAVAILABLE, 0);
            fixture(13); memset(guard + page - 4, 'p', 4);
            word(node, 128, (uintptr_t)(guard + page - 4));
            invoke(pointer, JM_READ_FAILED, 0);
        } else {
            word(scb, 80, 0); invoke(pointer, JM_UNAVAILABLE, JM_UNAVAILABLE);
            fixture(13); word(scb, 80, 1); invoke(pointer, JM_OUT_OF_SCOPE, JM_OUT_OF_SCOPE);
            fixture(13); word(client, 72, 1); invoke(pointer, JM_OUT_OF_SCOPE, JM_OUT_OF_SCOPE);
            fixture(13); word(peer, 184, 0); invoke(pointer, JM_UNAVAILABLE, JM_UNAVAILABLE);
            fixture(13); word(peer, 184, 2); invoke(pointer, JM_READ_FAILED, JM_READ_FAILED);
            fixture(13); word(member, 0, 0); invoke(pointer, JM_UNAVAILABLE, JM_COMPLETE);
            fixture(13); word(pool, 32, 1); invoke(pointer, JM_READ_FAILED, JM_COMPLETE);
            fixture(13); memset(guard + page - 4, 'p', 4);
            word(pool, 32, (uintptr_t)(guard + page - 4));
            invoke(pointer, JM_READ_FAILED, JM_COMPLETE);
        }
        invoke(0, JM_UNAVAILABLE, kind == 1 ? 0 : JM_UNAVAILABLE);
        invoke(2, JM_READ_FAILED, kind == 1 ? 0 : JM_READ_FAILED);
        fixture(13); refused = 1; invoke(pointer, JM_COMPLETE, endpoint);
        assert(!last.field.output_failures);
        refused = 0; invoke(pointer, JM_COMPLETE, endpoint);
        assert(last.field.output_failures == 1);
        ubpf_destroy(vm);
        printf("PASS %s kind=%u: exact values, bounds, unreadable memory, unchanged input, refusal\n",
                mode ? "JIT" : "interpreter", kind);
    }
    munmap(guard, page * 2);
    free(obj);
    return 0;
}
