/*
 * ls_shield_ubpf.bpf.c — the Live Shield as eBPF bytecode for an EMBEDDED
 * userspace VM (uBPF). This is the real TMM model (design §3.1, §6.1):
 * the host (minimm/TMM) calls the VM at a designed-in hook point and acts on
 * the return value. No kernel, no maps, no injection, no bpf_override_return.
 *
 * The host passes a struct ls_ctx as the program's memory argument and reads
 * back a verdict code:
 *   0 = PASS              (predicate did not match)
 *   1 = MATCH / MONITOR   (matched; host counts it but still passes -> crash, §7.1)
 *   2 = MATCH / ENFORCE   (matched; host counts + drops)
 *
 * Compile:  clang -O2 -target bpf -c ls_shield_ubpf.bpf.c -o ls_shield_ubpf.bpf.o
 */
#include <stdint.h>

struct ls_ctx {
	uint16_t opcode;
	uint16_t payload_len;
	uint32_t avail_len;
	uint32_t mode;        /* host fills in current mode: 1=monitor 2=enforce */
	uint8_t  head[16];
};

#define N_HANDLERS 4
#define LS_MONITOR 1
#define LS_ENFORCE 2

uint64_t ls_decision(void *data)
{
	struct ls_ctx *ctx = data;

	/* SIRT-derived crash precondition: opcode outside the handler table. */
	if (ctx->opcode >= N_HANDLERS) {
		if (ctx->mode == LS_ENFORCE)
			return 2;   /* matched + drop */
		return 1;           /* matched + monitor (host passes, then crashes) */
	}
	return 0;                   /* no match */
}
