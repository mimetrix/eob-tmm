/* Native interpreter/JIT check for surfaces/aigw_record.bpf.c.
 * Authored records of several lengths are passed as (hctx, publisher, line,
 * len); every emitted frame is reassembled and compared byte for byte. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

#define AR_CHUNK 128u
#define AR_CHUNKS 12u
struct ar_frame {
    uint32_t magic, abi;
    uint64_t instance, sequence, monotonic_ns;
    uint32_t total_len, chunk, chunks, copied;
    uint32_t flags, reserved;
    unsigned char data[AR_CHUNK];
};
_Static_assert(sizeof(struct ar_frame) == 184, "frame");

static struct ar_frame frames[AR_CHUNKS + 1];
static unsigned nframes, refuse;
static int mode;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    (void)slot;
    assert(size == sizeof(struct ar_frame) && nframes <= AR_CHUNKS);
    memcpy(&frames[nframes++], data, size);
    return refuse ? -1 : 0;
}

static void call(struct ubpf_vm *vm, ubpf_jit_ex_fn fn, uint64_t line, uint64_t len)
{
    uint64_t ctx[12] = {0x1111, 0x2222, line, len}, saved[12], ret = 99;
    unsigned char stack[4096] = {0};
    memcpy(saved, ctx, sizeof saved);
    nframes = 0;
    g_ls_cur_slot = 4; ls_config_begin(&g_ls_config_view, 4);
    if (mode) ret = fn(ctx, sizeof ctx, stack, sizeof stack);
    else assert(!ubpf_exec_ex(vm, ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0; g_ls_cur_slot = -1;
    assert(ret == 0 && !memcmp(saved, ctx, sizeof saved));
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *f = fopen(argv[1], "rb");
    assert(f && !fseek(f, 0, SEEK_END));
    long size = ftell(f);
    void *object = malloc(size);
    assert(!fseek(f, 0, SEEK_SET) && fread(object, 1, size, f) == (size_t)size);
    fclose(f);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED && !mprotect(guard + page, page, PROT_NONE));
    static unsigned char line[8192];
    for (unsigned i = 0; i < sizeof line; i++) line[i] = (unsigned char)('a' + i % 26);
    g_ls_config.session = 42;
    assert(ls_ranges_current(1));
    for (mode = 0; mode < 2; mode++) {
        char *error = NULL;
        struct ls_config_request r = {0};
        assert(!ls_map_reset_shapes());
        r.abi = r.schema = r.entries = 1; r.session = 42;
        r.instance = ls_config_new_instance(&g_ls_config, 4);
        r.revision = 1; memset(r.program_sha256, 7, 32);
        g_ls_config.loading = r.instance;
        struct ubpf_vm *vm = ubpf_create();
        assert(vm && !ls_map_glue_install(vm));
        assert(!ubpf_load_elf_ex(vm, object, size, "aigw_record", &error));
        ubpf_jit_ex_fn fn = ubpf_compile_ex(vm, &error, ExtendedJitMode);
        assert(fn);
        assert(!ls_config_bind(&g_ls_config, 4, r.instance, r.program_sha256));
        assert(!ls_config_publish(&g_ls_config, 4, &r, 112));
        g_ls_config.loading = 0;
        const uint64_t lens[] = {1, 127, 128, 129, 300, 1536, 1537, 4096};
        uint64_t seq = 0;
        for (unsigned k = 0; k < sizeof lens / sizeof lens[0]; k++) {
            uint64_t len = lens[k];
            unsigned want = (unsigned)((len + AR_CHUNK - 1) / AR_CHUNK);
            int trunc = want > AR_CHUNKS;
            if (trunc) want = AR_CHUNKS;
            call(vm, fn, (uintptr_t)line, len);
            assert(nframes == want);
            seq++;
            for (unsigned i = 0; i < nframes; i++) {
                struct ar_frame *fr = &frames[i];
                uint64_t off = (uint64_t)i * AR_CHUNK;
                uint32_t n = len - off >= AR_CHUNK ? AR_CHUNK : (uint32_t)(len - off);
                assert(fr->magic == 0x41474f42u && fr->abi == 1);
                assert(fr->instance == r.instance && fr->sequence == seq);
                assert(fr->total_len == len && fr->chunk == i && fr->chunks == want);
                assert(fr->copied == n && !memcmp(fr->data, line + off, n));
                for (unsigned j = n; j < AR_CHUNK; j++) assert(fr->data[j] == 0);
                assert(fr->flags == (trunc ? 8u : 0u));
            }
        }
        /* Null line, zero length, absurd length: one frame, BAD_ARGS. */
        call(vm, fn, 0, 10); assert(nframes == 1 && (frames[0].flags & 16));
        call(vm, fn, (uintptr_t)line, 0); assert(nframes == 1 && (frames[0].flags & 16));
        call(vm, fn, (uintptr_t)line, 1u << 20); assert(nframes == 1 && (frames[0].flags & 16));
        /* A record that runs into an unreadable page: READ_FAILED, never a crash. */
        memset(guard + page - 100, 'z', 100);
        call(vm, fn, (uintptr_t)(guard + page - 100), 300);
        assert(nframes == 3 && (frames[0].flags & 4));
        /* Output refusal is counted, and every chunk is still attempted. */
        refuse = 1; call(vm, fn, (uintptr_t)line, 300); refuse = 0;
        assert(nframes == 3);
        ubpf_destroy(vm);
        printf("PASS %s: lengths, truncation, bad args, unreadable tail, refusal\n",
                mode ? "JIT" : "interpreter");
    }
    munmap(guard, page * 2);
    free(object);
    return 0;
}
