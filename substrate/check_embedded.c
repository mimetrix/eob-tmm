/* P17 host oracle: native offsetof/layout and values, then execute relocated BPF
 * with the pinned uBPF interpreter and JIT. This is NOT a live TMM test. */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ubpf.h>

struct leaf {
    unsigned char padding[11];
    uint32_t value;
    uint16_t other;
    unsigned flag : 1;
    uint32_t array[2];
    union { uint32_t x; uint64_t y; } unsupported;
    struct { uint32_t hidden; } anonymous;
};
typedef struct leaf leaf_t;
struct middle {
    uint64_t padding;
    const volatile leaf_t embedded;
    const leaf_t *ptr;
};
typedef struct middle middle_t;
/* Kept as global definitions so GCC emits their BTF even without probe reads. */
struct only_embedded { middle_t nested; } only_embedded;
struct bit_zero { unsigned flag : 1; } bit_zero;
struct root {
    uint64_t padding[3];
    middle_t nested;
    leaf_t *direct;
    middle_t *middle_ptr;
    uint32_t scalar;
};
static struct leaf leaf = { .value = 789, .other = 31 };
static struct middle middle = { .embedded = { .value = 456, .other = 23 }, .ptr = &leaf };
static struct root root = {
    .nested = { .embedded = { .value = 123, .other = 17 }, .ptr = &leaf },
    .direct = &leaf, .middle_ptr = &middle, .scalar = 55
};
static unsigned reads, deny;

static int within(uint64_t src, uint64_t len, const void *base, size_t size)
{
    uint64_t start = (uintptr_t)base;
    return src >= start && src - start <= size && len <= size - (src - start);
}

static uint64_t probe_read(uint64_t dst, uint64_t len, uint64_t src,
                           uint64_t unused1, uint64_t unused2)
{
    (void)unused1; (void)unused2;
    reads++;
    if (deny || !(within(src, len, &root, sizeof root) ||
                  within(src, len, &leaf, sizeof leaf) ||
                  within(src, len, &middle, sizeof middle))) return (uint64_t)-1;
    memcpy((void *)(uintptr_t)dst, (void *)(uintptr_t)src, (size_t)len);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--offsets")) {
        printf("{\"root\":{\"nested\":%zu,\"direct\":%zu,\"middle_ptr\":%zu,\"scalar\":%zu},"
               "\"middle\":{\"embedded\":%zu,\"ptr\":%zu},"
               "\"leaf\":{\"value\":%zu,\"other\":%zu}}\n",
               offsetof(struct root, nested), offsetof(struct root, direct),
               offsetof(struct root, middle_ptr), offsetof(struct root, scalar),
               offsetof(struct middle, embedded), offsetof(struct middle, ptr),
               offsetof(struct leaf, value), offsetof(struct leaf, other));
        return 0;
    }
    if (argc != 6) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f || fseek(f, 0, SEEK_END)) return 2;
    long len = ftell(f);
    if (len <= 0 || fseek(f, 0, SEEK_SET)) return 2;
    void *obj = malloc((size_t)len);
    if (!obj || fread(obj, 1, (size_t)len, f) != (size_t)len) return 2;
    fclose(f);
    uint64_t ctx[12] = { (uintptr_t)&root, (uintptr_t)&root, 42 };
    if (!strcmp(argv[3], "null-root")) ctx[0] = ctx[1] = 0;
    if (!strcmp(argv[3], "null-pointer") || !strcmp(argv[3], "bad-pointer")) {
        uintptr_t p = !strcmp(argv[3], "bad-pointer") ? 1 : 0;
        root.direct = (struct leaf *)p;
        root.middle_ptr = (struct middle *)p;
        root.nested.ptr = (struct leaf *)p;
    }
    deny = !strcmp(argv[3], "read-failure");
    uint64_t want = strtoull(argv[4], NULL, 0);
    unsigned want_reads = (unsigned)strtoul(argv[5], NULL, 0);
    struct ubpf_vm *vm = ubpf_create();
    char *err = NULL;
    if (!vm || ubpf_register(vm, 4, "bpf_probe_read", probe_read) ||
        ubpf_load_elf_ex(vm, obj, (size_t)len, argv[2], &err)) {
        fprintf(stderr, "uBPF load: %s\n", err ? err : "failed"); return 2;
    }
    ubpf_jit_fn jit = ubpf_compile(vm, &err);
    if (!jit) { fprintf(stderr, "JIT: %s\n", err); return 2; }
    int failed = 0;
    for (int j = 0; j < 2; j++) {
        uint64_t got = 0;
        reads = 0;
        if (j) got = jit(ctx, sizeof ctx);
        else if (ubpf_exec(vm, ctx, sizeof ctx, &got)) return 2;
        int ok = got == want && reads == want_reads;
        printf("%s %s: value=%llu want=%llu helper_reads=%u want=%u %s\n",
               j ? "JIT" : "interpreter", argv[3], (unsigned long long)got,
               (unsigned long long)want, reads, want_reads, ok ? "PASS" : "MISMATCH");
        failed |= !ok;
    }
    ubpf_destroy(vm);
    free(obj);
    return failed;
}
