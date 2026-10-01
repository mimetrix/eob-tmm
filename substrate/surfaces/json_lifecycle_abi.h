#ifndef JSON_LIFECYCLE_ABI_H
#define JSON_LIFECYCLE_ABI_H
#include "json_method_abi.h"
#define JL_MAGIC 0x4a4c4244u
struct jl_event {
    jm_u32 magic, abi;
    jm_u64 instance, revision, run, monotonic_ns, sequence;
    jm_u64 output_failures, context_tag;
    jm_u32 kind, code, status, flags, flow_side, scb_flags;
    jm_u32 cache_present, seen_mask, reads, source_bytes;
    jm_u32 payload_bytes, reserved;
};
_Static_assert(sizeof(struct jl_event) == 112, "boundary record ABI");
#endif
