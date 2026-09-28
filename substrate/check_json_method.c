/* Exact extraction with real VM/read/map helpers and an authored output sink. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include "surfaces/json_method_abi.h"
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

static struct jm_event last;
static unsigned emissions, refuse, reads, source_bytes;
static struct jm_value val, root;
static uint64_t object[5];
static struct { struct jm_member p; uint64_t prev; } members[5];
static struct { uint64_t base; uint32_t len, pad; } str;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == 7 && size == sizeof last);
    memcpy(&last, data, size);
    assert(last.magic == 0x4a4d4554 && last.abi == 1);
    emissions++;
    return refuse ? -1 : 0;
}

static uint64_t tracked_read(uint64_t dst, uint64_t n, uint64_t src,
        uint64_t a, uint64_t b)
{
    reads++;
    source_bytes += n;
    return ls_h_probe_read(dst, n, src, a, b);
}

static void fixture(unsigned position, uint64_t base, unsigned length)
{
    memset(&val, 0, sizeof val);
    memset(&root, 0, sizeof root);
    memset(object, 0, sizeof object);
    memset(members, 0, sizeof members);
    val.owner = (uintptr_t)&root;
    root.type = 1;
    root.flags = 1;
    root.value[0] = (uintptr_t)object;
    object[2] = (uintptr_t)&members[position];
    for (unsigned i = 0; i <= position; i++) {
        members[i].p.key = (uintptr_t)"other";
        members[i].p.len = 5;
        members[i].p.flags = 1;
        members[i].p.next = (uintptr_t)&members[(i + 1) % (position + 1)];
    }
    members[position].p.key = (uintptr_t)"method";
    members[position].p.len = 6;
    members[position].p.value = (uintptr_t)&val;
    str.base = base;
    str.len = length;
}

static void invoke(struct ubpf_vm *vm, ubpf_jit_ex_fn jit, int mode,
        uint64_t value, uint64_t descriptor, uint64_t result, unsigned status)
{
    uint64_t ctx[12] = {value, descriptor}, ret = 99;
    uint8_t stack[4096] = {0};
    ctx[5] = result;
    emissions = reads = source_bytes = 0;
    g_ls_cur_slot = 7;
    ls_config_begin(&g_ls_config_view, 7);
    if (mode)
        ret = jit(ctx, sizeof ctx, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    assert(ret == 0 && emissions == 1 && last.status == status);
    assert(last.getter_result == (uint32_t)result);
    assert(last.reads == reads && last.source_bytes == source_bytes);
    assert(reads <= 12 && source_bytes <= 320);
    assert(last.copied_length <= 64);
    if (status != JM_COMPLETE && status != JM_TRUNCATED)
        assert(!last.copied_length);
    for (unsigned i = last.copied_length; i < 64; i++)
        assert(last.value[i] == 0);
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++)
        printf("%02x", ((const unsigned char *)&last)[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *f = fopen(argv[1], "rb");
    assert(f && !fseek(f, 0, SEEK_END));
    long size = ftell(f);
    assert(size > 0 && !fseek(f, 0, SEEK_SET));
    void *obj = malloc(size);
    assert(obj && fread(obj, 1, size, f) == (size_t)size);
    fclose(f);
    long page = sysconf(_SC_PAGESIZE);
    char *guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED && !mprotect(guard + page, page, PROT_NONE));
    memset(guard, 'x', page);
    assert(ls_ranges_current(1));
    g_ls_config.session = 42;
    for (int mode = 0; mode < 2; mode++) {
        char *error = NULL;
        assert(!ls_map_reset_shapes());
        struct ls_config_request r = {0};
        r.abi = r.schema = r.entries = 1;
        r.session = 42;
        r.instance = ls_config_new_instance(&g_ls_config, 7);
        r.revision = 1;
        memset(r.program_sha256, 7, 32);
        uint64_t token = 123;
        memcpy(r.rows, &token, 8);
        g_ls_config.loading = r.instance;
        struct ubpf_vm *vm = ubpf_create();
        assert(vm && !ls_map_glue_install(vm));
        assert(!ubpf_register(vm, 4, "tracked_read", tracked_read));
        assert(!ubpf_load_elf_ex(vm, obj, size, "json_method", &error));
        ubpf_jit_ex_fn jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
        assert(!ls_config_bind(&g_ls_config, 7, r.instance, r.program_sha256));
        invoke(vm, jit, mode, 1, 1, 0, JM_UNAVAILABLE);
        assert(last.flags == 1 && !last.reads);
        assert(!ls_config_publish(&g_ls_config, 7, &r, 112));
        const char *values[] = {"SendMessage", "future.variant", "",
            "future\\u002evariant"};
        for (unsigned i = 0; i < sizeof values / sizeof *values; i++) {
            unsigned n = strlen(values[i]);
            fixture(i, (uintptr_t)values[i], n);
            invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0, JM_COMPLETE);
            assert(last.original_length == n && last.copied_length == n);
            assert(!memcmp(last.value, values[i], n) && !last.flags);
        }
        unsigned lengths[] = {0, 1, 63, 64, 65};
        for (unsigned i = 0; i < sizeof lengths / sizeof *lengths; i++) {
            unsigned n = lengths[i];
            fixture(3, (uintptr_t)(guard + page - n), n);
            invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0,
                    n > 64 ? JM_TRUNCATED : JM_COMPLETE);
            assert(last.original_length == n && last.copied_length == (n > 64 ? 64 : n));
            assert(!memcmp(last.value, guard + page - n, last.copied_length));
        }
        fixture(4, (uintptr_t)"hidden", 6);
        invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0, JM_BUDGET);
        fixture(0, 1, 6);
        invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0, JM_READ_FAILED);
        str.base = (uintptr_t)(guard + page - 3);
        invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0, JM_READ_FAILED);
        invoke(vm, jit, mode, (uintptr_t)&val, 1, 0, JM_READ_FAILED);
        invoke(vm, jit, mode, 1, 1, 0, JM_READ_FAILED);
        invoke(vm, jit, mode, 1, 1, UINT64_MAX, JM_GETTER_ERROR);
        assert(!last.reads);
        fixture(0, (uintptr_t)"private", 7);
        root.owner = 1;
        invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0, JM_OUT_OF_SCOPE);
        root.owner = 0;
        members[0].p.key = (uintptr_t)"secret";
        invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0, JM_OUT_OF_SCOPE);
        fixture(0, (uintptr_t)"future.variant", 14);
        refuse = 1;
        invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0, JM_COMPLETE);
        assert(!last.output_failures);
        refuse = 0;
        invoke(vm, jit, mode, (uintptr_t)&val, (uintptr_t)&str, 0, JM_COMPLETE);
        assert(last.output_failures == 1);
        ubpf_destroy(vm);
        printf("PASS %s: exact strings, escapes, bounds, guard pages, failures, scope, budget, refusal\n",
                mode ? "JIT" : "interpreter");
    }
    munmap(guard, page * 2);
    free(obj);
    return 0;
}
