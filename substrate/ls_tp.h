/* ls_tp.h --- the tracepoint boundary crossing.
 *
 * TMM compiles in two include worlds. Files marked STDINC in src/compile/filelist
 * get the standard C library; files without it get TMM's -nostdinc universe. The
 * VM (ls_vm.c) lives in the first. Every file in modules/hudfilter/http lives in
 * the second. A tracepoint placed in TMM's own logic therefore has to cross.
 *
 * This header is the whole crossing, and it is deliberately dependency-free: it
 * declares one function using only types that are ABI-identical on both sides.
 * `unsigned long` is size_t on x86_64 LP64, so the STDINC side can forward it to
 * ls_vm_call(int, void *, size_t) with no conversion. Nothing else crosses.
 *
 * DO NOT "simplify" this by redeclaring ls_vm_call's real prototype on the
 * -nostdinc side. That is the same mistake ls_prep.c documents: an enum return
 * is not an int return, `bool` comes back in al while `int` reads eax, and the
 * upper bits are not guaranteed. It is an ABI mismatch, not a style question.
 */
#ifndef LS_TP_H
#define LS_TP_H

/*
 * Hand a built tracepoint record to the VM. Returns nothing --- ON PURPOSE.
 *
 * A tracepoint is an observer. Giving the call site no way to receive a verdict
 * means it has no way to act on one, so the tracepoint cannot alter traffic even
 * if the program loaded behind it is armed in ENFORCE. That is a structural
 * guarantee rather than a mode setting, and it is the difference between this
 * and a shield: a shield exists precisely to change the outcome, so it takes the
 * verdict and the host decides whether to apply it.
 *
 * This matters because relying on MONITOR mode alone has already gone wrong once
 * --- a tracepoint armed while an earlier ENFORCE setting was still in effect
 * turned 200s into 404s. A void return makes that class of accident impossible
 * here instead of merely unlikely.
 *
 * Safe to call from any TMM thread at any point: it does not allocate, does not
 * lock, does not enter the kernel, and falls through when the slot is empty.
 */
void ls_tp_emit(int slot, const void *rec, unsigned long len);

/*
 * Slot assignment. Slot 0 is the shield --- the built-in program compiled into
 * the binary, and whatever replaces it over the loader socket. Tracepoints get
 * their own slots so that arming or revoking a shield never disturbs telemetry,
 * and so a STATUS query can report them independently (ls_vm_load.c takes the
 * slot from the request rather than assuming 0).
 */
#define LS_TP_SLOT_HTTP_HDRS 1

#endif /* LS_TP_H */
