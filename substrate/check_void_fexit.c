/* Native fixture, not the TMM JSON handler. Link with --wrap=ls_fexit_enter.
 * The real entry trampoline, shadow stack and return stub remain unchanged.
 * Entry capture below is the candidate adapter; ls_vm_call is a test observer.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "ls_fexit.h"
#include "check_snapshot_stubs.h"

enum { INIT = 57, DEPTH = 512, MAX_EVENTS = 1024 };
enum action { PLAIN, DISABLE, ENABLE, NEST, RECURSE, PROTECT, SKIP, OUTER_SKIP };
struct object { unsigned disabled, initialized; };
struct snapshot { uint64_t event, serial; unsigned known, eligible; };
struct observation { uint64_t serial; unsigned known, completed; };
static struct snapshot snapshots[DEPTH];
static struct observation observations[MAX_EVENTS];
static unsigned count, final_writes, omit_capture;
static size_t page_size;
static jmp_buf jump;
uint64_t cv_return_noise;
extern int g_ls_fexit_top;
extern void cv_target(struct object *, uint64_t, uint64_t, uint64_t, uint64_t);
extern void __real_ls_fexit_enter(int, uint64_t *, const uint64_t *);

void __wrap_ls_fexit_enter(int slot, uint64_t *address, const uint64_t *args)
{
    int index = g_ls_fexit_top;
    __real_ls_fexit_enter(slot, address, args);
    if (g_ls_fexit_top == index) return; /* overflow: no new frame */
    assert(index >= 0 && index < DEPTH && g_ls_fexit_top == index + 1);
    struct snapshot *s = &snapshots[index];
    memset(s, 0, sizeof *s);
    s->event = args[1];
    s->serial = args[4];
    if (omit_capture) return;
    const struct object *o = (const void *)(uintptr_t)args[0];
    s->known = 1;
    s->eligible = args[1] == INIT && o != NULL && !o->disabled;
}

/* The real leave function has already matched and popped the returning frame.
 * Do not dereference c->arg[0] or read c->ret here. */
enum ls_verdict ls_vm_call(int slot, void *context, size_t size)
{
    const struct ls_ctx_exit *c = context;
    assert(slot == 1 && size == sizeof *c && count < MAX_EVENTS);
    assert(g_ls_fexit_top >= 0 && g_ls_fexit_top < DEPTH);
    const struct snapshot *s = &snapshots[g_ls_fexit_top];
    assert(s->event == c->arg[1] && s->serial == c->arg[4]);
    observations[count++] = (struct observation){s->serial, s->known,
                                                  s->known && s->eligible};
    return LS_FALLTHROUGH;
}
uint64_t ls_vm_safe_value(int slot) { (void)slot; return 0; }

/* Source-derived control flow only. These are fixture fields, not TMM layouts. */
void cv_body(struct object *o, uint64_t event, uint64_t action,
             uint64_t depth, uint64_t serial)
{
    if (o && !o->disabled && event == INIT) {
        memset(o, 0, sizeof *o);
        o->initialized = 1;
        final_writes++;
    }
    switch (action) {
    case DISABLE: o->disabled = 1; break;
    case ENABLE: o->disabled = 0; break;
    case NEST:
        /* The same address is re-entered with the opposite entry condition. */
        o->disabled = !o->disabled;
        cv_target(o, event, PLAIN, 0, serial + 1);
        break;
    case RECURSE:
        if (depth) cv_target(o, event, RECURSE, depth - 1, serial + 1);
        break;
    case PROTECT:
        assert(o->initialized == 1);
        assert(mprotect(o, page_size, PROT_NONE) == 0);
        break;
    case SKIP: longjmp(jump, 1);
    case OUTER_SKIP:
        if (setjmp(jump) == 0) cv_target(o, event, SKIP, 0, serial + 1);
        break;
    default: break;
    }
}

static void reset(void)
{
    assert(g_ls_fexit_top == 0);
    ls_fexit_reset();
    memset(snapshots, 0, sizeof snapshots);
    memset(observations, 0, sizeof observations);
    count = final_writes = omit_capture = 0;
}

static void check(unsigned index, uint64_t serial, unsigned known, unsigned complete)
{
    assert(index < count);
    assert(observations[index].serial == serial);
    assert(observations[index].known == known);
    assert(observations[index].completed == complete);
}

int main(void)
{
    struct object o;
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    for (unsigned noise = 0; noise < 2; noise++) {
        cv_return_noise = noise ? UINT64_C(0xfedcba9876543210) : 0;
        reset(); o = (struct object){0};
        cv_target(&o, INIT, PLAIN, 0, 1);
        check(0, 1, 1, 1);
        assert(count == 1 && final_writes == 1 && o.initialized == 1);

        reset(); o = (struct object){1, 0};
        cv_target(&o, INIT, ENABLE, 0, 2);
        check(0, 2, 1, 0);
        assert(count == 1 && final_writes == 0 && o.disabled == 0);

        reset(); o = (struct object){0};
        cv_target(&o, INIT, DISABLE, 0, 3);
        check(0, 3, 1, 1);
        assert(count == 1 && final_writes == 1 && o.disabled == 1);

        reset();
        cv_target(NULL, INIT, PLAIN, 0, 4);
        check(0, 4, 1, 0);
        assert(count == 1 && final_writes == 0);

        reset(); o = (struct object){0};
        cv_target(&o, 2, PLAIN, 0, 5);
        check(0, 5, 1, 0);
        assert(count == 1 && final_writes == 0);

        reset(); o = (struct object){0};
        cv_target(&o, INIT, NEST, 0, 6);
        check(0, 7, 1, 0); check(1, 6, 1, 1);
        assert(count == 2 && final_writes == 1);

        reset(); o = (struct object){0};
        cv_target(&o, INIT, RECURSE, 7, 8);
        assert(count == 8 && final_writes == 8);
        for (unsigned i = 0; i < count; i++) check(i, 15 - i, 1, 1);

        reset(); o = (struct object){0};
        for (unsigned i = 0; i < 20; i++) {
            o.disabled = i & 1;
            cv_target(&o, INIT, PLAIN, 0, i);
            check(i, i, 1, !(i & 1));
        }
        assert(count == 20 && final_writes == 10);

        reset();
        struct object *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        assert(page != MAP_FAILED);
        cv_target(page, INIT, PROTECT, 0, 20);
        check(0, 20, 1, 1);
        assert(count == 1 && final_writes == 1);
        assert(munmap(page, page_size) == 0);

        reset(); o = (struct object){0};
        cv_target(&o, INIT, OUTER_SKIP, 0, 21);
        check(0, 21, 1, 1);
        assert(count == 1 && final_writes == 2 && g_ls_fexit_reclaimed == 1);

        reset(); o = (struct object){0};
        cv_target(&o, INIT, RECURSE, DEPTH + 1, 22);
        assert(count == DEPTH && final_writes == DEPTH + 2);
        assert(g_ls_fexit_overflow == 2 && g_ls_fexit_desync == 0);
        for (unsigned i = 0; i < count; i++) check(i, 22 + DEPTH - 1 - i, 1, 1);

        reset(); o = (struct object){0}; omit_capture = 1;
        cv_target(&o, INIT, PLAIN, 0, 23);
        check(0, 23, 0, 0);
        assert(count == 1 && final_writes == 1);
        assert(g_ls_fexit_top == 0 && g_ls_fexit_desync == 0);
        printf("PASS noise=%u cases=12 observed_returns=550\n", noise);
    }
    puts("PASS void completion: native adapter, no return-value use, no post-return reads");
    return 0;
}
