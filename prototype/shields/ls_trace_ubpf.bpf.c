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
 * Compile:  clang -O2 -target bpf -c ls_trace_ubpf.bpf.c -o ls_trace_ubpf.bpf.o
 */
#include <stdint.h>

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
	return ctx->opcode;   /* sampled field; host buckets it (trace[opcode & 7]) */
}
