/* Native interpreter/JIT check for surfaces/aigw_timing.bpf.c.
 * Seven VMs from one ELF share the program's maps. An authored request runs
 * admit -> store send/reply -> FORWARDED -> server reply parse -> server done
 * -> client done -> publish; every event must carry the same scb key, the
 * admit time, rising timestamps and the point's own fields. Then the
 * negative cases: inactive node, unreadable context, missing scb. */
#define LS_MAP_GLUE_IMPL 1
#include "ls_map_glue.h"
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>

struct at_event {
    uint32_t magic, abi;
    uint64_t instance, sequence, monotonic_ns, scb;
    uint32_t point, flags, a, b;
    uint64_t admit_ns;
};
_Static_assert(sizeof(struct at_event) == 64, "event");

static struct at_event last;
static unsigned emitted;
static int mode;

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    (void)slot;
    assert(size == sizeof last);
    memcpy(&last, data, size);
    emitted++;
    return 0;
}

/* index -> function; point = POINT[index] */
#define NFN 8
static const char *fns[NFN] = {"at_admit", "at_store_hgetall", "at_store_reply",
    "at_event", "at_reply_parse", "at_reply_done", "at_publish", "at_store_eval"};
static const unsigned POINT[NFN] = {1, 2, 3, 4, 5, 6, 7, 2};
static struct ubpf_vm *vms[NFN];
static ubpf_jit_ex_fn jit[NFN];

static struct at_event call(unsigned which, uint64_t a0, uint64_t a1,
        uint64_t a2, uint64_t a3, uint64_t a4)
{
    uint64_t ctx[12] = {a0, a1, a2, a3, a4}, saved[12], ret = 99;
    unsigned char stack[4096] = {0};
    memcpy(saved, ctx, sizeof saved);
    emitted = 0;
    g_ls_cur_slot = 4; ls_config_begin(&g_ls_config_view, 4);
    if (mode) ret = jit[which](ctx, sizeof ctx, stack, sizeof stack);
    else assert(!ubpf_exec_ex(vms[which], ctx, sizeof ctx, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0; g_ls_cur_slot = -1;
    assert(ret == 0 && emitted == 1 && !memcmp(saved, ctx, sizeof saved));
    assert(last.magic == 0x41544d47u && last.abi == 1 && last.point == POINT[which]);
    return last;
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
    g_ls_config.session = 42;
    assert(ls_ranges_current(1));
    for (mode = 0; mode < 2; mode++) {
        struct ls_config_request r = {0};
        assert(!ls_map_reset_shapes());
        r.abi = r.schema = r.entries = 1; r.session = 42;
        r.instance = ls_config_new_instance(&g_ls_config, 4);
        r.revision = 1; memset(r.program_sha256, 7, 32);
        g_ls_config.loading = r.instance;
        for (unsigned i = 0; i < NFN; i++) {
            char *error = NULL;
            vms[i] = ubpf_create();
            assert(vms[i] && !ls_map_glue_install(vms[i]));
            int rc = ubpf_load_elf_ex(vms[i], object, size, fns[i], &error);
            if (rc) fprintf(stderr, "%s: %s\n", fns[i], error);
            assert(!rc);
            jit[i] = ubpf_compile_ex(vms[i], &error, ExtendedJitMode);
            assert(jit[i]);
        }
        assert(!ls_config_bind(&g_ls_config, 4, r.instance, r.program_sha256));
        assert(!ls_config_publish(&g_ls_config, 4, &r, 112));
        g_ls_config.loading = 0;

        /* A hudnode: flags word at +44 with f_active|f_ctx, scb inline at +64.
         * Two host contexts whose scb pointer (+24) names that scb. */
        static _Alignas(64) unsigned char node[64 + 160], other[64 + 160];
        static _Alignas(8) uint64_t hc[14];
        memset(node, 0, sizeof node); memset(other, 0, sizeof other);
        uint32_t bits = 3u << 22;
        memcpy(node + 44, &bits, 4); memcpy(other + 44, &bits, 4);
        uint64_t scb = (uintptr_t)(node + 64), scb2 = (uintptr_t)(other + 64);
        hc[3] = scb;

        struct at_event e[10];
        e[0] = call(0, (uintptr_t)node, 0x1111, 0x2222, 0, 0);       /* admit */
        e[1] = call(1, (uintptr_t)hc, 0x20, 64, 9, 0);               /* hgetall, token 9 */
        e[2] = call(2, (uintptr_t)hc, 7, 0x40, 0, 0);                /* reply */
        e[3] = call(7, (uintptr_t)hc, 0, 0x30, 8, 0x40);             /* eval (enforce) */
        e[4] = call(2, (uintptr_t)hc, 8, 0x40, 0, 0);                /* reply */
        e[5] = call(3, scb, 4, 0, 0, 0);                             /* FORWARDED */
        e[6] = call(4, (uintptr_t)hc, 1, 0, 0, 0);                   /* server parse */
        e[7] = call(5, scb, 1, 0, 0, 0);                             /* server done */
        e[8] = call(5, scb, 0, 0, 0, 0);                             /* client done */
        e[9] = call(6, (uintptr_t)hc, 0x50, 0x60, 970, 0);           /* publish */
        for (unsigned i = 0; i < 10; i++) {
            assert(e[i].scb == scb && !e[i].flags && e[i].instance == r.instance);
            assert(e[i].admit_ns == e[0].monotonic_ns);
            if (i) assert(e[i].monotonic_ns >= e[i - 1].monotonic_ns &&
                          e[i].sequence == e[i - 1].sequence + 1);
        }
        assert(e[1].a == 1 && e[1].b == 1 && e[2].a == 1 && e[3].a == 2);
        assert(e[5].a == 4 && e[6].a == 1 && e[7].a == 1 && e[8].a == 0);
        assert(e[9].b == 970);

        /* A second request on another scb keeps its own start; a new admit on
         * the first scb (keep-alive) replaces that scb's start. */
        struct at_event o = call(0, (uintptr_t)other, 0, 0, 0, 0);
        struct at_event o2 = call(3, scb2, 4, 0, 0, 0);
        assert(o2.scb == scb2 && o2.admit_ns == o.monotonic_ns);
        assert(call(3, scb, 4, 0, 0, 0).admit_ns == e[0].monotonic_ns);
        struct at_event again = call(0, (uintptr_t)node, 0, 0, 0, 0);
        assert(call(5, scb, 0, 0, 0, 0).admit_ns == again.monotonic_ns);

        /* Negative cases emit one event with the reason and no key. */
        uint32_t off = 0;
        memcpy(node + 44, &off, 4);
        struct at_event n = call(0, (uintptr_t)node, 0, 0, 0, 0);
        assert(!n.scb && (n.flags & 4) && !n.admit_ns);
        memcpy(node + 44, &bits, 4);
        n = call(0, (uintptr_t)(guard + page - 8), 0, 0, 0, 0);
        assert(!n.scb && (n.flags & 2));
        n = call(4, (uintptr_t)(guard + page - 8), 1, 0, 0, 0);
        assert(!n.scb && (n.flags & 2));
        n = call(1, 0, 0, 0, 0, 0);
        assert(!n.scb && (n.flags & 2));
        n = call(7, 0, 0, 0, 0, 0);            /* detached eval, NULL ctx */
        assert(!n.scb && (n.flags & 2) && n.a == 2);
        n = call(3, 0, 4, 0, 0, 0);
        assert(!n.scb && (n.flags & 4));
        n = call(5, 0x1234, 0, 0, 0, 0);       /* unknown scb: no start */
        assert(n.scb == 0x1234 && !n.admit_ns && !n.flags);
        for (unsigned i = 0; i < NFN; i++) ubpf_destroy(vms[i]);
        printf("PASS %s: one request across eight entries, two scbs, keep-alive, negatives\n",
                mode ? "JIT" : "interpreter");
    }
    munmap(guard, page * 2);
    free(object);
    return 0;
}
