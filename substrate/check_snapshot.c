/* Production VM + production return frames. Authored target and output sink. */
#define LS_MAP_GLUE_IMPL
#include "ls_vm.c"
#include "ls_fexit.h"
#include "check_snapshot_abi.h"
#include <assert.h>
#include <setjmp.h>

enum { INIT = 57, DEPTH = 512, MAX_EVENTS = 1024 };
enum action { PLAIN, DISABLE, ENABLE, NEST, RECURSE, PROTECT, SKIP,
              OUTER_SKIP, RELOAD, OMIT, BAD_READ, SMASH, PAUSE, RESTORE,
              RESTORE_FUEL };
struct object { unsigned disabled, initialized; };
static struct snapshot_observation observations[MAX_EVENTS];
static unsigned count, writes, reads;
static size_t page_size, replacement_len;
static void *replacement;
static jmp_buf jump;
uint64_t cv_return_noise;
extern int g_ls_fexit_top;
extern uint64_t g_ls_fexit_seq;
extern void cv_target(struct object *, uint64_t, uint64_t, uint64_t, uint64_t);

int ls_tp_publish_raw(int slot, const void *record, unsigned long length)
{
    assert(slot == 1 && length == sizeof observations[0]);
    assert(count < MAX_EVENTS);
    memcpy(&observations[count++], record, length);
    return 0;
}

int ls_tp_emit_shield(int slot, unsigned gen, unsigned mode, unsigned verdict,
                      const void *ctx, unsigned long length)
{
    (void)slot; (void)gen; (void)mode; (void)verdict; (void)ctx; (void)length;
    assert(!"completion mode emitted a shield verdict");
    return -1;
}

static uint64_t tracked_read(uint64_t dst, uint64_t size, uint64_t src,
                              uint64_t a4, uint64_t a5)
{
    reads++;
    return ls_h_probe_read(dst, size, src, a4, a5);
}

static void load(void *blob, size_t length)
{
    g_ls_config.loading = ls_config_new_instance(&g_ls_config, 1);
    assert(g_ls_config.loading != 0);
    assert(ls_vm_reload(1, blob, length, "fexit/snapshot/snapshot_victim",
                        "snapshot_probe", LS_MODE_MONITOR) == 1);
    g_ls_config.loading = 0;
    assert(!ubpf_register(g_slots[1].vm, 4, "tracked_read", tracked_read));
    assert((g_slots[1].jit_fn != NULL) == g_cfg.jit);
}

void cv_body(struct object *o, uint64_t event, uint64_t action,
              uint64_t depth, uint64_t serial)
{
    if (action != BAD_READ && o && !o->disabled && event == INIT) {
        memset(o, 0, sizeof *o);
        o->initialized = 1;
        writes++;
    }
    switch (action) {
    case DISABLE: o->disabled = 1; break;
    case ENABLE: o->disabled = 0; break;
    case NEST:
        o->disabled = !o->disabled;
        cv_target(o, event, PLAIN, 0, serial + 1);
        break;
    case RECURSE:
        if (depth) cv_target(o, event, RECURSE, depth - 1, serial + 1);
        break;
    case PROTECT:
        assert(o->initialized == 1);
        assert(!mprotect(o, page_size, PROT_NONE));
        break;
    case SKIP: longjmp(jump, 1);
    case OUTER_SKIP:
        if (!setjmp(jump)) cv_target(o, event, SKIP, 0, serial + 1);
        break;
    case RELOAD: load(replacement, replacement_len); break;
    case PAUSE:
        ls_vm_set_mode(1, LS_MODE_DISABLE);
        ls_vm_set_mode(1, LS_MODE_MONITOR);
        break;
    case RESTORE: g_slots[1].armed = true; break;
    case RESTORE_FUEL:
        ubpf_set_instruction_limit(g_slots[1].vm, 10000, NULL);
        break;
    default: break;
    }
}

static void reset(void)
{
    assert(g_ls_fexit_top == 0);
    ls_fexit_reset();
    memset(observations, 0, sizeof observations);
    count = writes = reads = 0;
}

static void check(unsigned index, uint64_t serial, unsigned known,
                   unsigned eligible, unsigned owner)
{
    assert(index < count);
    const struct snapshot_observation *o = &observations[index];
    assert(o->serial == serial && o->known == known);
    assert(o->eligible == eligible && o->owner == owner);
    assert(o->phase == LS_SNAPSHOT_RETURN && o->no_return == 0);
    assert(o->sequence != 0 && o->sequence != UINT64_MAX);
    assert(!known || (o->marker == owner && o->flags == LS_SNAPSHOT_CAPTURED));
}

static void *read_object(const char *path, size_t *length)
{
    FILE *file = fopen(path, "rb");
    assert(file && !fseek(file, 0, SEEK_END));
    long size = ftell(file);
    assert(size > 0 && !fseek(file, 0, SEEK_SET));
    void *data = malloc((size_t)size);
    assert(data && fread(data, 1, (size_t)size, file) == (size_t)size);
    assert(!fclose(file));
    *length = (size_t)size;
    return data;
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    size_t initial_len = 0;
    void *initial = read_object(argv[1], &initial_len);
    replacement = read_object(argv[2], &replacement_len);
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    assert(ls_vm_init());
    for (unsigned noise = 0; noise < 2; noise++) {
        struct object o = {0};
        load(initial, initial_len);
        cv_return_noise = noise ? UINT64_C(0xfedcba9876543210) : 0;
        reset(); cv_target(&o, INIT, PLAIN, 0, 1);
        check(0, 1, 1, 1, 1); assert(count == 1 && writes == 1 && reads == 1);

        reset(); o = (struct object){1, 0};
        cv_target(&o, INIT, ENABLE, 0, 2);
        check(0, 2, 1, 0, 1); assert(count == 1 && writes == 0);
        reset(); o = (struct object){0};
        cv_target(&o, INIT, DISABLE, 0, 3);
        check(0, 3, 1, 1, 1); assert(count == 1 && writes == 1);
        reset(); cv_target(NULL, INIT, PLAIN, 0, 4);
        check(0, 4, 1, 0, 1); assert(count == 1 && writes == 0 && reads == 0);
        reset(); o = (struct object){0};
        cv_target(&o, 2, PLAIN, 0, 5);
        check(0, 5, 1, 0, 1); assert(count == 1 && writes == 0);

        reset(); o = (struct object){0};
        cv_target(&o, INIT, NEST, 0, 6);
        check(0, 7, 1, 0, 1); check(1, 6, 1, 1, 1);
        assert(count == 2 && writes == 1 && reads == 2);
        assert(observations[0].sequence > observations[1].sequence);
        reset(); o = (struct object){0};
        cv_target(&o, INIT, RECURSE, 7, 8);
        assert(count == 8 && writes == 8 && reads == 8);
        for (unsigned i = 0; i < count; i++) check(i, 15 - i, 1, 1, 1);

        reset(); o = (struct object){0};
        for (unsigned i = 0; i < 20; i++) {
            o.disabled = i & 1;
            cv_target(&o, INIT, PLAIN, 0, i);
            check(i, i, 1, !(i & 1), 1);
        }
        assert(count == 20 && writes == 10 && reads == 20);
        reset();
        struct object *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(page != MAP_FAILED);
        cv_target(page, INIT, PROTECT, 0, 20);
        check(0, 20, 1, 1, 1); assert(count == 1 && reads == 1);
        assert(!munmap(page, page_size));

        reset(); o = (struct object){0};
        cv_target(&o, INIT, OUTER_SKIP, 0, 21);
        check(0, 21, 1, 1, 1);
        assert(count == 1 && writes == 2 && g_ls_fexit_reclaimed == 1);
        reset(); o = (struct object){0};
        cv_target(&o, INIT, RECURSE, DEPTH + 1, 22);
        assert(count == DEPTH && writes == DEPTH + 2 && reads == DEPTH);
        assert(g_ls_fexit_overflow == 2 && g_ls_fexit_desync == 0);
        for (unsigned i = 0; i < count; i++) check(i, 22 + DEPTH - 1 - i, 1, 1, 1);

        reset(); o = (struct object){0};
        cv_target(&o, INIT, OMIT, 0, 23);
        check(0, 23, 0, 0, 1); assert(count == 1 && writes == 1);
        reset(); cv_target((void *)1, INIT, BAD_READ, 0, 24);
        check(0, 24, 0, 0, 1); assert(count == 1 && writes == 0 && reads == 1);
        reset(); o = (struct object){0};
        cv_target(&o, INIT, SMASH, 0, 25);
        check(0, 25, 1, 1, 1);
        assert(observations[0].node == (uintptr_t)&o && observations[0].event == INIT);
        assert(writes == 1 && count == 1);

        reset(); o = (struct object){0};
        uint64_t rejected = g_slots[1].snapshot_return_errors;
        cv_target(&o, INIT, PAUSE, 0, 26);
        assert(count == 0 && writes == 1);
        assert(g_slots[1].snapshot_return_errors == rejected + 1);
        reset(); o = (struct object){0};
        uint64_t failed = g_slots[1].snapshot_entry_errors;
        g_slots[1].armed = false; /* Inject a missing VM at entry only. */
        cv_target(&o, INIT, RESTORE, 0, 27);
        check(0, 27, 0, 0, 1); assert(observations[0].flags == 0);
        assert(count == 1 && g_slots[1].snapshot_entry_errors == failed + 1);

        reset(); o = (struct object){0};
        rejected = g_slots[1].snapshot_return_errors;
        cv_target(&o, INIT, RELOAD, 0, 28);
        assert(count == 0 && writes == 1);
        assert(g_slots[1].snapshot_return_errors == rejected + 1);
        cv_target(&o, INIT, PLAIN, 0, 29);
        check(0, 29, 1, 1, 2); assert(count == 1);

        reset(); o = (struct object){0};
        g_ls_fexit_seq = UINT64_MAX;
        cv_target(&o, INIT, PLAIN, 0, 30);
        assert(count == 0 && writes == 1 && g_ls_fexit_overflow == 1);
        reset(); o = (struct object){0};
        g_slots[1].snapshot_id.epoch = UINT64_MAX;
        cv_target(&o, INIT, PLAIN, 0, 31);
        assert(count == 0 && writes == 1);
        load(initial, initial_len);
        if (!g_cfg.jit) {
            reset(); o = (struct object){0};
            failed = g_slots[1].snapshot_entry_errors;
            ubpf_set_instruction_limit(g_slots[1].vm, 8, NULL);
            cv_target(&o, INIT, RESTORE_FUEL, 0, 32);
            check(0, 32, 0, 0, 1); assert(observations[0].flags == 0);
            assert(count == 1 && g_slots[1].snapshot_entry_errors == failed + 1);
        }
        assert(g_ls_fexit_top == 0 && g_ls_fexit_desync == 0);
        assert(g_slots[1].safe_returns == 0);
        printf("PASS snapshot jit=%d noise=%u cases=%u\n",
               g_cfg.jit, noise, g_cfg.jit ? 19 : 20);
    }
    ls_vm_fini();
    free(initial); free(replacement);
    return 0;
}
