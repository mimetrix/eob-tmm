/* ls_tp_emit.c --- the STDINC side of the tracepoint boundary.
 *
 * Six lines of real work. It exists as its own translation unit because the
 * caller cannot reach ls_vm.h: every file in modules/hudfilter/http compiles in
 * TMM's -nostdinc world, and ls_vm.h needs stdint/stddef. This file is marked
 * STDINC in src/compile/filelist and is the only place the two worlds meet for
 * telemetry --- the same shape ls_prep.c already uses for the bootstrap.
 *
 * WHY THE VERDICT IS DISCARDED HERE. ls_vm_call returns one, because the shield
 * path needs it. A tracepoint does not, and giving the call site no way to
 * receive it means no future edit at that call site can accidentally start
 * acting on it. The cast to void is the entire safety property, and it is
 * cheaper and more durable than a mode check --- see ls_tp.h.
 */
#include "ls_tp.h"
#include "ls_vm.h"

void
ls_tp_emit(int slot, const void *rec, unsigned long len)
{
    /*
     * ls_vm_call takes void*, not const void*, because a verified program may
     * legally write every byte of what it is handed: PREVAIL does not consume a
     * `writable: []` annotation, so it cannot express a read-only region
     * (finding O1). The cast is safe HERE for a reason specific to this path ---
     * `rec` points at the caller's own stack record, built fresh for this
     * invocation and dead when it returns. A program that scribbles on it
     * corrupts nothing but its own input.
     *
     * That is exactly why the record is a stack copy rather than a view onto
     * TMM state. Handing a program a pointer into hd->ci would turn a telemetry
     * mechanism into a way to modify the parsed request.
     */
    (void)ls_vm_call(slot, (void *)(unsigned long)rec, (size_t)len);
}
