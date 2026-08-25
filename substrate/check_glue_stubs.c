/* check_glue_stubs.c --- recording stand-ins for uBPF's three registrars.
 *
 * Stubs rather than the real library because what is under test is OUR sequence:
 * that all five registrations happen, that relocation is first, and that a
 * partial install is reported as a failure. The real ubpf_register* calls would
 * succeed silently and prove none of that.
 *
 * fail_at makes the Nth registration refuse, which is how the all-or-nothing
 * property is tested rather than asserted in a comment.
 */
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "ubpf.h"

char calls[256];
int  ncalls;
int  fail_at = -1;

static int
bump(const char *what)
{
    if (ncalls == fail_at) { ncalls++; return -1; }
    if (strlen(calls) + strlen(what) + 2 < sizeof calls) {
        strcat(calls, what);
        strcat(calls, " ");
    }
    ncalls++;
    return 0;
}

int
ubpf_register_data_relocation(struct ubpf_vm *vm, void *c, ubpf_data_relocation r)
{ (void)vm; (void)c; (void)r; return bump("reloc"); }

int
ubpf_register_data_bounds_check(struct ubpf_vm *vm, void *c, ubpf_bounds_check b)
{ (void)vm; (void)c; (void)b; return bump("bounds"); }

int
ubpf_register(struct ubpf_vm *vm, unsigned int idx, const char *n, external_function_t f)
{
    (void)vm; (void)n; (void)f;
    return bump(idx == 1 ? "h1" : idx == 2 ? "h2" : idx == 3 ? "h3"
              : idx == 4 ? "h4" : idx == 5 ? "h5" : idx == 25 ? "h25" : idx == 112 ? "h112" : "h?");
}

/* ls_tp_publish_raw lives in ls_tp_emit.c, which this test does not link --- the point
 * here is the glue, not the ring. Stubbed so the ringbuf helper's REFUSAL paths can be
 * exercised without a segment: every one of them returns before reaching this, so a call
 * arriving here means a guard was missed. Counted, so "publish did not happen" is
 * asserted rather than assumed. */
int  ls_tp_publish_calls;
unsigned long ls_tp_publish_len;

int
ls_tp_publish_raw(int slot, const void *rec, unsigned long len)
{
    (void)slot; (void)rec;
    ls_tp_publish_calls++;
    ls_tp_publish_len = len;
    return 0;
}
