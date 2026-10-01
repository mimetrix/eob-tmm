/* Independent authored-token fixtures exercise the real VM and guarded reads. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include "surfaces/message_id_abi.h"
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
static struct tm_token tokens[128];
static struct tm_frag fragments[5];
static char raw[2048];
static struct jm_event last;
static unsigned count, refuse, reads, bytes_read, source_flags = 0x24;
static struct ubpf_vm *vm;
static ubpf_jit_ex_fn jit;
static int mode;

#ifndef LS_ACTIVITY_TEST
int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == 11 && size == sizeof last);
    memcpy(&last, data, size); count++;
    return refuse ? -1 : 0;
}
#endif

static uint64_t tracked_read(uint64_t dst, uint64_t n, uint64_t src,
        uint64_t a, uint64_t b)
{
    reads++; bytes_read += n;
    return ls_h_probe_read(dst, n, src, a, b);
}

static unsigned encode(unsigned *pos)
{
    unsigned id = cache.used++;
    assert(id < 128);
    struct tm_token *t = &tokens[id];
    while (raw[*pos] == ' ') (*pos)++;
    t->start = *pos; t->sibling = -1;
    char c = raw[(*pos)++];
    if (c == '{' || c == '[') {
        t->type = c == '{' ? 1 : 2;
        unsigned previous = 0;
        while (raw[*pos] != (c == '{' ? '}' : ']')) {
            if (raw[*pos] == ',' || raw[*pos] == ' ') { (*pos)++; continue; }
            unsigned child = encode(pos);
            if (previous) tokens[previous].sibling = child;
            if (c == '{') {
                assert(raw[*pos] == ':'); (*pos)++;
                unsigned value = encode(pos);
                tokens[child].size = 1; tokens[child].sibling = value;
                previous = value;
            } else previous = child;
            t->size++;
        }
        t->end = ++(*pos);
    } else if (c == '"') {
        t->type = 3; t->start = *pos;
        while (raw[*pos] != '"') {
            assert(raw[*pos]);
            if (raw[*pos] == '\\') (*pos)++;
            (*pos)++;
        }
        t->end = (*pos)++;
    } else {
        t->type = 4;
        while (raw[*pos] && !strchr(",}] ", raw[*pos])) (*pos)++;
        t->end = *pos;
    }
    return id;
}

static void split(unsigned n)
{
    unsigned offset = 0;
    memset(fragments, 0, sizeof fragments);
    for (unsigned i = 0; i < n; i++) {
        unsigned len = (cache.len - offset) / (n - i);
        fragments[i].base = (uintptr_t)raw;
        fragments[i].offset = offset; fragments[i].len = len;
        fragments[i].next = i + 1 < n ? (uintptr_t)&fragments[i + 1] : 0;
        offset += len;
    }
    cache.head = (uintptr_t)fragments;
}

static void fixture(const char *text)
{
    memset(&cache, 0, sizeof cache); memset(tokens, 0, sizeof tokens);
    memset(raw, 0, sizeof raw); assert(strlen(text) < sizeof raw);
    strcpy(raw, text);
    unsigned pos = 0;
    encode(&pos); assert(pos == strlen(text));
    cache.root = cache.valid = cache.ref = 1;
    cache.len = pos; cache.capacity = cache.limit = 128;
    cache.tokens = (uintptr_t)tokens; split(1);
}

static void invoke(uint64_t pointer, unsigned status, unsigned kind,
        const char *value)
{
    uint64_t scb[12] = {0}, ctx[12] = {0, (uintptr_t)scb}, ret = 99;
    uint8_t stack[4096] = {0};
    unsigned char before[sizeof cache + sizeof tokens + sizeof fragments + sizeof raw] = {0};
    scb[3] = pointer; scb[11] = source_flags;
    memcpy(before, &cache, sizeof cache);
    memcpy(before + sizeof cache, tokens, sizeof tokens);
    memcpy(before + sizeof cache + sizeof tokens, fragments, sizeof fragments);
    memcpy(before + sizeof cache + sizeof tokens + sizeof fragments, raw, sizeof raw);
    count = reads = bytes_read = 0;
    g_ls_cur_slot = 11; ls_config_begin(&g_ls_config_view, 11);
    if (mode) ret = jit(ctx, sizeof ctx, stack, sizeof stack);
    else assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0; g_ls_cur_slot = -1;
    if (last.status != status || last.getter_result != kind)
        fprintf(stderr, "%s expected %u/%u got %u/%u\n", raw,
                status, kind, last.status, last.getter_result);
    assert(ret == 0 && count == 1 && last.status == status);
    assert(last.magic == MI_MAGIC && last.abi == 1 && last.getter_result == kind);
    assert(last.reads == reads && last.source_bytes == bytes_read);
    assert(reads <= 80 && bytes_read <= 2048 && last.copied_length <= 64);
    assert(!memcmp(before, &cache, sizeof cache));
    assert(!memcmp(before + sizeof cache, tokens, sizeof tokens));
    assert(!memcmp(before + sizeof cache + sizeof tokens, fragments, sizeof fragments));
    assert(!memcmp(before + sizeof cache + sizeof tokens + sizeof fragments, raw, sizeof raw));
    if (value) {
        unsigned n = strlen(value);
        assert(last.original_length == n && last.copied_length == (n > 64 ? 64 : n));
        assert(!memcmp(last.value, value, last.copied_length));
    } else assert(!last.copied_length);
    for (unsigned i = last.copied_length; i < 64; i++) assert(!last.value[i]);
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++) printf("%02x", ((unsigned char *)&last)[i]);
    puts("");
}
#define CALL(s,k,v) invoke((uintptr_t)&cache,s,k,v)

static void unhex(const char *hex, char *out, unsigned capacity)
{
    unsigned n = strlen(hex);
    assert(!(n % 2) && n / 2 < capacity);
    for (unsigned i = 0; i < n / 2; i++) {
        unsigned b = 0;
        assert(sscanf(hex + i * 2, "%2x", &b) == 1); out[i] = b;
    }
    out[n / 2] = 0;
}

int main(int argc, char **argv)
{
    assert(argc == 3 && sizeof cache == 72);
    FILE *file = fopen(argv[1], "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long size = ftell(file);
    assert(size > 0 && !fseek(file, 0, SEEK_SET));
    void *obj = malloc(size);
    assert(obj && fread(obj, 1, size, file) == (size_t)size); fclose(file);
    long page = sysconf(_SC_PAGESIZE);
    char *guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED && !mprotect(guard + page, page, PROT_NONE));
    assert(ls_ranges_current(1)); g_ls_config.session = 42;
    for (mode = 0; mode < 2; mode++) {
        char *error = NULL;
        struct ls_config_request r = {0};
        uint64_t run = 123;
        assert(!ls_map_reset_shapes());
        r.abi = r.schema = r.entries = 1; r.session = 42;
        r.instance = ls_config_new_instance(&g_ls_config, 11); r.revision = 1;
        memset(r.program_sha256, 11, 32); memcpy(r.rows, &run, 8);
        g_ls_config.loading = r.instance;
        vm = ubpf_create(); assert(vm && !ls_map_glue_install(vm));
        assert(!ubpf_register(vm, 4, "tracked_read", tracked_read));
        assert(!ubpf_load_elf_ex(vm, obj, size, "message_id", &error));
        jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
        assert(!ls_config_bind(&g_ls_config, 11, r.instance, r.program_sha256));
        CALL(7,0,NULL); assert(last.flags == 1 && !reads);
        assert(!ls_config_publish(&g_ls_config, 11, &r, 112));
        FILE *cases = fopen(argv[2], "r"); assert(cases);
        unsigned status = 0, kind = 0;
        int n = 0;
        char hex[4096] = {0}, value_hex[256] = {0};
        char text[2048] = {0}, value[128] = {0};
        while ((n = fscanf(cases, "%u %u %255s %4095s", &status, &kind, value_hex, hex)) != EOF) {
            assert(n == 4);
            unhex(hex, text, sizeof text);
            value[0] = 0;
            if (value_hex[0] != '-' && value_hex[0] != '_')
                unhex(value_hex, value, sizeof value);
            fixture(text); CALL(status, kind, value_hex[0] == '-' ? NULL : value);
        }
        fclose(cases);
        const char *invalid[] = {"01", "-01", "1.", "1e", "1e+", "--1", "+1", ".5", "NaN", "Infinity", "-", "1e2.3"};
        for (unsigned i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
            snprintf(text, sizeof text, "{\"id\":%s}", invalid[i]);
            fixture(text); CALL(10,0,NULL);
        }
        const char *sample = "{\"id\":\"sample\"}";
        fixture(sample); split(4); CALL(1,1,"sample");
        fixture(sample); split(5); CALL(5,1,NULL);
        fixture(sample); tokens[2].end = cache.len + 1; CALL(9,0,NULL);
        fixture(sample); tokens[1].start = -1; CALL(9,0,NULL);
        fixture(sample); cache.valid = 0; CALL(9,0,NULL);
        fixture(sample); cache.used = 129; CALL(9,0,NULL);
        fixture(sample); source_flags = 4; CALL(4,0,NULL);
        source_flags = 0x1024; CALL(4,0,NULL); source_flags = 0x24;
        fixture(sample); cache.tokens = 1; CALL(3,0,NULL);
        fixture(sample); fragments[0].base = 1; CALL(3,0,NULL);
        fixture(sample);
        unsigned cut = tokens[2].start + 2;
        memcpy(guard + page - cut, raw, cut);
        fragments[0].base = (uintptr_t)(guard + page - cut);
        CALL(3,1,NULL);
        invoke(0, 7, 0, NULL);
        fixture(sample); refuse = 1; CALL(1,1,"sample"); assert(!last.output_failures);
        refuse = 0; CALL(1,1,"sample"); assert(last.output_failures == 1);
        ubpf_destroy(vm);
        printf("PASS %s: ID type/bytes, number grammar, limits, guarded reads, unchanged input, refusal\n",
                mode ? "JIT" : "interpreter");
    }
    munmap(guard, page * 2); free(obj); return 0;
}
