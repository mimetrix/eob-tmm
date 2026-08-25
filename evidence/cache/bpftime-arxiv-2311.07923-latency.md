# bpftime latency figures — extracted 2026-08-25T16:49:24Z

Source: "bpftime: userspace eBPF Runtime for Uprobe, Syscall and Kernel-User Interactions"
arXiv:2311.07923  (https://arxiv.org/abs/2311.07923 · html: https://arxiv.org/html/2311.07923v2)
Retrieved 2026-08-25T16:49:24Z via WebSearch summary of the paper + project README
(https://github.com/eunomia-bpf/bpftime). NOTE: figures are from the paper's reported
benchmarks as surfaced in search/abstract; the full PDF was NOT byte-cached, so treat as
CITED-FROM-ABSTRACT, not a verified full-text cache. Re-pull the PDF to promote to MEASURED-EXTERNAL.

## Reported latency (nanoseconds per call)
- kernel uprobe        : 3224.17
- kernel uretprobe     : 3996.80
- bpftime uprobe (userspace)    : 314.57
- bpftime uretprobe (userspace) : 381.27
- bpftime runtime embedding overhead : ~110.01

## Mechanism (from README)
- Hooking by BINARY REWRITING; userspace-function path "inspired by frida-gum".
- Verifier: PREVAIL (userspace) or the kernel verifier. (SAME verifier this project uses.)
- Maps: interprocess eBPF maps in shared userspace memory.
- Injection: LD_PRELOAD loader OR inject into an already-running process without restart.
- Claim: "up to 10x speedup in Uprobe overhead vs kernel uprobe/uretprobe."
- Root cause of kernel cost: int3 trap + two context switches (kernel<->user), 10-20x slowdown.

## Our comparable number (this repo, GROUND_TRUTH.md / bench_tramp.c)
- trampoline mechanism : 8.76 ns (measured, hot-cache microbench, min-of-batches, 2.60 GHz)
- full observe hook    : ~14 ns
