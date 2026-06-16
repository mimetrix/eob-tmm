/*
 * ls_trace_ubpf.bpf.c — an OBSERVE-mode tracepoint for the embedded uBPF VM.
 *
 * It reads the data-plane frame and RETURNS A SAMPLED VALUE (here the opcode);
 * the host histograms it for telemetry and never changes traffic flow. This is
 * eBPF observability running INSIDE the kernel-bypassing data plane — the thing
 * kernel-based observability ("eob") structurally cannot see. Same VM, same
 * hook point, same §9 verify gate as the enforcement shield; only the host's
 * use of the result differs (telemetry vs verdict).
 *
 * It also doubles as a FLIGHT RECORDER (substrate §3.1): the host keeps a ring
 * of recent frames, and this program ARMS A DUMP by OR-ing LS_FR_TRIGGER into
 * its return when it sees the crash precondition. The low byte stays the
 * histogram sample; the high bit is the trigger. The dump captures the run-up
 * INTO the failure — the state a post-crash core dump no longer has.
 *
 * Return: bits [7:0] = sampled opcode (host buckets trace[sample & 7]);
 *         bit  [8]   = LS_FR_TRIGGER (host freezes + dumps the ring).
 *
 * Compile:  clang -O2 -target bpf -c ls_trace_ubpf.bpf.c -o ls_trace_ubpf.bpf.o
 */
#include <stdint.h>

#define N_HANDLERS    4        /* must match minimm's handler table          */
#define LS_FR_TRIGGER 0x100u   /* must match ls_shield.h                      */

struct ls_ctx {
	uint16_t opcode;
	uint16_t payload_len;
	uint32_t avail_len;
	uint32_t mode;
	uint8_t  head[16];
};

uint64_t ls_decision(void *data)
{
	struct ls_ctx *ctx = data;
	uint64_t r = ctx->opcode & 0xff;   /* sampled field; host buckets it */
	if (ctx->opcode >= N_HANDLERS)     /* crash precondition = the trigger */
		r |= LS_FR_TRIGGER;        /* arm the flight-recorder dump */
	return r;
}
