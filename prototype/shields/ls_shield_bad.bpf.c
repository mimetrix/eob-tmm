/*
 * ls_shield_bad.bpf.c — a DELIBERATELY UNSAFE shield, to demonstrate the §9
 * verify-before-load gate rejecting it. It performs an out-of-bounds read far
 * past the context memory the host provides. A static verifier (PREVAIL) should
 * reject this BEFORE the VM ever runs it; without the gate, uBPF would fault at
 * runtime (i.e. the shield itself would take down the data plane — exactly what
 * the gate exists to prevent).
 *
 * Compile:  clang -O2 -target bpf -c ls_shield_bad.bpf.c -o ls_shield_bad.bpf.o
 */
#include <stdint.h>

uint64_t ls_decision(void *data)
{
	uint8_t *p = data;
	/* wild read ~1 MiB past the context -> memory-safety violation */
	return (uint64_t)p[1 << 20];
}
