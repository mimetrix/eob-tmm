#ifndef REPLY_METADATA_ABI_H
#define REPLY_METADATA_ABI_H
#include "token_method_abi.h"
#define RP_MAGIC 0x52504c59u
#define RP_AMBIGUOUS 11u
#define RP_WRONG_TYPE 10u
struct rp_event {
    jm_u32 magic, abi;
    jm_u64 instance, revision, run, monotonic_ns, sequence, output_failures;
    jm_u32 flags, reads, source_bytes, status, result_present, error_present;
    jm_u32 code_state;
    int error_code;
    jm_u32 tool_error_state, tool_error, reserved[2];
};
_Static_assert(sizeof(struct rp_event) == 104, "reply ABI");
#endif
