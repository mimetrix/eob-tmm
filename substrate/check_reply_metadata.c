/* Authored JSON fixtures drive the real interpreter and JIT on the build box. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include "surfaces/reply_metadata_abi.h"
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
static struct rp_event last;
static unsigned count, refuse, reads, bytes_read, source_flags = 0x24;
static struct ubpf_vm *vm;
static ubpf_jit_ex_fn jit;
static int mode;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    assert(slot == 11 && size == sizeof last);
    memcpy(&last, data, size);
    count++;
    return refuse ? -1 : 0;
}

static uint64_t tracked_read(uint64_t dst, uint64_t n, uint64_t src,
        uint64_t a, uint64_t b)
{
    reads++; bytes_read += n;
    return ls_h_probe_read(dst, n, src, a, b);
}

/* Encode fixture JSON recursively, independent of probe lookup. */
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
    cache.tokens = (uintptr_t)tokens;
    split(1);
}

static void invoke(uint64_t pointer, const int expected[7])
{
    uint64_t scb[12] = {0}, ctx[12] = {0, (uintptr_t)scb}, ret = 99;
    uint8_t stack[4096] = {0};
    unsigned char before[sizeof cache + sizeof tokens + sizeof fragments + sizeof raw];
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
    int actual[] = {last.status, last.result_present, last.error_present,
        last.code_state, last.error_code, last.tool_error_state, last.tool_error};
    for (unsigned i = 0; i < 7; i++) {
        if (actual[i] != expected[i])
            fprintf(stderr, "%s field %u expected %d got %d\n", raw, i, expected[i], actual[i]);
        assert(actual[i] == expected[i]);
    }
    assert(ret == 0 && count == 1 && last.magic == RP_MAGIC && last.abi == 1);
    assert(last.reads == reads && last.source_bytes == bytes_read);
    assert(reads <= 80 && bytes_read <= 2048 && !last.reserved[0] && !last.reserved[1]);
    assert(!memcmp(before, &cache, sizeof cache));
    assert(!memcmp(before + sizeof cache, tokens, sizeof tokens));
    assert(!memcmp(before + sizeof cache + sizeof tokens, fragments, sizeof fragments));
    assert(!memcmp(before + sizeof cache + sizeof tokens + sizeof fragments, raw, sizeof raw));
    printf("RECORD ");
    for (size_t i = 0; i < sizeof last; i++) printf("%02x", ((unsigned char *)&last)[i]);
    puts("");
}
#define CALL(...) invoke((uintptr_t)&cache, (int[]){__VA_ARGS__})

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
        assert(!ubpf_load_elf_ex(vm, obj, size, "reply_metadata", &error));
        jit = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        if (!jit) { fprintf(stderr, "%s\n", error); return 1; }
        assert(!ls_config_bind(&g_ls_config, 11, r.instance, r.program_sha256));
        CALL(7,0,0,0,0,0,0); assert(last.flags == 1 && !reads);
        assert(!ls_config_publish(&g_ls_config, 11, &r, 112));
        FILE *cases = fopen(argv[2], "r"); assert(cases);
        int expected[7], n;
        char hex[4096], text[2048];
        while ((n = fscanf(cases, "%d %d %d %d %d %d %d %4095s",
                expected, expected + 1, expected + 2, expected + 3,
                expected + 4, expected + 5, expected + 6, hex)) != EOF) {
            assert(n == 8 && !(strlen(hex) % 2));
            unsigned length = strlen(hex) / 2;
            for (unsigned i = 0; i < length; i++) {
                unsigned b; assert(sscanf(hex + i * 2, "%2x", &b) == 1);
                text[i] = b;
            }
            text[length] = 0; fixture(text); invoke((uintptr_t)&cache, expected);
        }
        fclose(cases);
        const char *sample = "{\"result\":{\"isError\":true}}";
        fixture(sample); split(4); CALL(1,1,0,0,0,1,1);
        fixture(sample); split(5); CALL(1,1,0,0,0,5,0);
        fixture(sample); tokens[4].end = cache.len + 1; CALL(1,1,0,0,0,9,0);
        fixture(sample); tokens[3].start = -1; CALL(1,1,0,0,0,9,0);
        fixture(sample); cache.valid = 0; CALL(9,0,0,0,0,0,0);
        fixture(sample); cache.used = 129; CALL(9,0,0,0,0,0,0);
        fixture(sample); source_flags = 4; CALL(4,0,0,0,0,0,0);
        source_flags = 0x1024; CALL(4,0,0,0,0,0,0); source_flags = 0x24;
        fixture(sample); cache.tokens = 1; CALL(3,0,0,0,0,0,0);
        fixture(sample); fragments[0].base = 1; CALL(3,0,0,0,0,0,0);
        fixture(sample);
        unsigned cut = tokens[4].start + 2;
        memcpy(guard + page - cut, raw, cut);
        fragments[0].base = (uintptr_t)(guard + page - cut);
        CALL(1,1,0,0,0,3,0);
        invoke(0, (int[]){7,0,0,0,0,0,0});
        fixture(sample); refuse = 1; CALL(1,1,0,0,0,1,1); assert(!last.output_failures);
        refuse = 0; CALL(1,1,0,0,0,1,1); assert(last.output_failures == 1);
        ubpf_destroy(vm);
        printf("PASS %s: exact fields, ambiguity, bounds, guarded reads, unchanged input, refusal\n",
                mode ? "JIT" : "interpreter");
    }
    munmap(guard, page * 2); free(obj); return 0;
}
