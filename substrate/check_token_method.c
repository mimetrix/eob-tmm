/* Authored token/fragment fixtures with real VM, map and read helpers. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include "surfaces/token_method_abi.h"
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

static struct {
    uint64_t root;
    uint32_t len, flags;
    uint64_t head, tail;
    uint32_t capacity, limit;
    uint64_t tokens;
    uint32_t pos, used;
    int super, prev;
    uint32_t valid, ref;
} cache;
static struct tm_token tokens[16];
static struct tm_frag fragments[5];
static char raw[1024];
static struct jm_event last;
static unsigned emissions, refuse, reads, source_bytes;
static uint32_t source_flags = 0x24;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == 7 && size == sizeof last);
    memcpy(&last, data, size);
    assert(last.magic == TM_MAGIC && last.abi == 1);
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

static void split(unsigned n)
{
    memset(fragments, 0, sizeof fragments);
    unsigned offset = 0;
    for (unsigned i = 0; i < n; i++) {
        unsigned len = (cache.len - offset) / (n - i);
        fragments[i].base = (uintptr_t)raw;
        fragments[i].offset = offset;
        fragments[i].len = len;
        fragments[i].next = i + 1 < n ? (uintptr_t)&fragments[i + 1] : 0;
        offset += len;
    }
    cache.head = (uintptr_t)fragments;
}

static void fixture(unsigned position, const char *value)
{
    memset(&cache, 0, sizeof cache);
    memset(tokens, 0, sizeof tokens);
    memset(raw, 0, sizeof raw);
    unsigned offset = 1;
    raw[0] = '{';
    for (unsigned i = 0; i <= position; i++) {
        const char *key = i == position ? "method" : "otherx";
        const char *v = i == position ? value : "private";
        if (i)
            raw[offset++] = ',';
        raw[offset++] = '"';
        tokens[1 + i * 2] = (struct tm_token){3, offset, offset + 6, 1, 2 + i * 2};
        memcpy(raw + offset, key, 6);
        offset += 6;
        memcpy(raw + offset, "\":\"", 3);
        offset += 3;
        tokens[2 + i * 2] = (struct tm_token){3, offset, offset + strlen(v), 0,
            i < position ? (int)(3 + i * 2) : -1};
        memcpy(raw + offset, v, strlen(v));
        offset += strlen(v);
        raw[offset++] = '"';
    }
    raw[offset++] = '}';
    tokens[0] = (struct tm_token){1, 0, offset, position + 1, -1};
    cache.root = 1;
    cache.len = offset;
    cache.capacity = cache.limit = 16;
    cache.tokens = (uintptr_t)tokens;
    cache.used = 3 + position * 2;
    cache.valid = cache.ref = 1;
    split(1);
}

static void invoke(struct ubpf_vm *vm, ubpf_jit_ex_fn jit, int mode,
        uint64_t pointer, unsigned status)
{
    uint64_t scb[12] = {0}, ctx[12] = {0, (uintptr_t)scb}, ret = 99;
    scb[3] = pointer;
    scb[11] = source_flags;
    uint8_t stack[4096] = {0};
    unsigned char before_cache[sizeof cache], before_tokens[sizeof tokens];
    char before_raw[sizeof raw];
    memcpy(before_cache, &cache, sizeof cache);
    memcpy(before_tokens, tokens, sizeof tokens);
    memcpy(before_raw, raw, sizeof raw);
    emissions = reads = source_bytes = 0;
    g_ls_cur_slot = 7;
    ls_config_begin(&g_ls_config_view, 7);
    if (mode)
        ret = jit(ctx, sizeof ctx, stack, sizeof stack);
    else
        assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0;
    g_ls_cur_slot = -1;
    if (last.status != status)
        fprintf(stderr, "expected %u got %u (reads %u)\n", status, last.status, reads);
    assert(ret == 0 && emissions == 1 && last.status == status);
    assert(last.reads == reads && last.source_bytes == source_bytes);
    assert(reads <= 40 && source_bytes <= 1024 && last.copied_length <= 64);
    assert(!memcmp(before_cache, &cache, sizeof cache));
    assert(!memcmp(before_tokens, tokens, sizeof tokens));
    assert(!memcmp(before_raw, raw, sizeof raw));
    if (status != JM_COMPLETE && status != JM_TRUNCATED)
        assert(!last.copied_length);
    for (unsigned i = last.copied_length; i < 64; i++)
        assert(!last.value[i]);
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++)
        printf("%02x", ((unsigned char *)&last)[i]);
    puts("");
}

int main(int argc, char **argv)
{
    assert(argc == 2 && sizeof cache == 72 && sizeof(struct tm_frag) == 24);
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
        assert(!ubpf_load_elf_ex(vm, obj, size, "token_method", &error));
        ubpf_jit_ex_fn jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
        assert(!ls_config_bind(&g_ls_config, 7, r.instance, r.program_sha256));
#define CALL(status) invoke(vm, jit, mode, (uintptr_t)&cache, status)
        CALL(JM_UNAVAILABLE);
        assert(last.flags == 1 && !last.reads);
        assert(!ls_config_publish(&g_ls_config, 7, &r, 112));
        const char *values[] = {"tools/list", "future.variant", "", "future\\u002evariant"};
        for (unsigned i = 0; i < 4; i++) {
            fixture(i, values[i]);
            split(i + 1);
            CALL(JM_COMPLETE);
            assert(last.original_length == strlen(values[i]));
            assert(last.copied_length == strlen(values[i]));
            assert(!memcmp(last.value, values[i], strlen(values[i])));
        }
        char text[66] = {0};
        memset(text, 'x', 65);
        for (unsigned n = 63; n <= 65; n++) {
            text[n] = 0;
            fixture(0, text);
            split(4);
            CALL(n > 64 ? JM_TRUNCATED : JM_COMPLETE);
            assert(last.original_length == n && last.copied_length == (n > 64 ? 64 : n));
            assert(!memcmp(last.value, text, last.copied_length));
            text[n] = 'x';
        }
        fixture(4, "late"); CALL(JM_BUDGET);
        fixture(0, "fragmented"); split(5); CALL(JM_BUDGET);
        fixture(0, "secret"); memcpy(raw + tokens[1].start, "params", 6); CALL(TM_NO_LITERAL_METHOD);
        fixture(0, "unused");
        strcpy(raw, "{\"params\":{\"method\":\"private\"},\"method\":\"visible\"}");
        cache.len = strlen(raw);
        unsigned end = strchr(raw, '}') - raw + 1;
        unsigned inner_key = strstr(raw, "method") - raw;
        unsigned inner_value = strstr(raw, "private") - raw;
        unsigned outer_key = strstr(raw + end, "method") - raw;
        unsigned outer_value = strstr(raw, "visible") - raw;
        tokens[0] = (struct tm_token){1, 0, cache.len, 2, -1};
        tokens[1] = (struct tm_token){3, 2, 8, 1, 2};
        tokens[2] = (struct tm_token){1, 10, end, 1, 5};
        tokens[3] = (struct tm_token){3, inner_key, inner_key + 6, 1, 4};
        tokens[4] = (struct tm_token){3, inner_value, inner_value + 7, 0, -1};
        tokens[5] = (struct tm_token){3, outer_key, outer_key + 6, 1, 6};
        tokens[6] = (struct tm_token){3, outer_value, outer_value + 7, 0, -1};
        cache.used = 7;
        split(3);
        CALL(JM_COMPLETE);
        assert(last.copied_length == 7 && !memcmp(last.value, "visible", 7));
        tokens[2].sibling = 3;
        CALL(TM_INVALID_CACHE);
        tokens[0].size = 1;
        tokens[0].end = end + 1;
        raw[end] = '}';
        cache.len = end + 1;
        split(1);
        CALL(TM_NO_LITERAL_METHOD);
        fixture(0, "unused");
        strcpy(raw, "{\"m\\u0065thod\":\"private\"}");
        cache.len = strlen(raw);
        tokens[0].end = cache.len;
        tokens[1].end = 13;
        tokens[2].start = 16;
        tokens[2].end = 23;
        split(1);
        CALL(TM_NO_LITERAL_METHOD);
        fixture(0, "secret"); tokens[0].type = 2; CALL(JM_OUT_OF_SCOPE);
        fixture(0, "7"); tokens[2].type = 4; CALL(TM_NONSTRING);
        fixture(0, "bad"); tokens[2].end = cache.len + 1; CALL(TM_INVALID_CACHE);
        fixture(0, "bad"); tokens[1].start = -1; CALL(TM_INVALID_CACHE);
        fixture(0, "bad"); cache.used = 17; CALL(TM_INVALID_CACHE);
        fixture(1, "bad"); tokens[2].sibling = 1; CALL(TM_INVALID_CACHE);
        fixture(0, "bad"); cache.valid = 0; CALL(TM_INVALID_CACHE);
        fixture(0, "bad"); cache.root = 0; CALL(TM_INVALID_CACHE);
        source_flags = 4; CALL(JM_OUT_OF_SCOPE);
        source_flags = 0x1024; CALL(JM_OUT_OF_SCOPE);
        source_flags = 0x24;
        fixture(0, "bad"); cache.tokens = 1; CALL(JM_READ_FAILED);
        fixture(0, "bad"); cache.head = 1; CALL(JM_READ_FAILED);
        fixture(0, "bad"); fragments[0].base = 1; CALL(JM_READ_FAILED);
        fixture(0, "partial-secret");
        memcpy(guard + page - 20, raw, 20);
        fragments[0].base = (uintptr_t)(guard + page - 20);
        CALL(JM_READ_FAILED);
        invoke(vm, jit, mode, 1, JM_READ_FAILED);
        invoke(vm, jit, mode, 0, JM_UNAVAILABLE);
        fixture(1, "second"); memcpy(raw + tokens[1].start, "method", 6);
        CALL(JM_COMPLETE); assert(last.copied_length == 7 && !memcmp(last.value, "private", 7));
        fixture(0, "tools/list"); refuse = 1; CALL(JM_COMPLETE);
        assert(!last.output_failures);
        refuse = 0; CALL(JM_COMPLETE); assert(last.output_failures == 1);
        ubpf_destroy(vm);
        printf("PASS %s: exact bytes, fragments, scope, corruption, guard page, unchanged source, refusal\n",
            mode ? "JIT" : "interpreter");
    }
    munmap(guard, page * 2);
    free(obj);
    return 0;
}
