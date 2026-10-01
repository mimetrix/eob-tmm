#ifndef RESPONSE_METADATA_ABI_H
#define RESPONSE_METADATA_ABI_H
#include "json_method_abi.h"
#define RM_MAGIC 0x5253504du
#define RM_NA 0u
#define RM_COMPLETE 1u
#define RM_READ_FAILED 3u
#define RM_OUT_OF_SCOPE 4u
#define RM_UNAVAILABLE 7u
struct rm_event {
    jm_u32 magic, abi;
    jm_u64 instance, revision, run, monotonic_ns, sequence;
    jm_u64 output_failures;
    jm_u32 code, presence, flags, reads, source_bytes;
    jm_u32 http_status_state, http_status;
    jm_u32 completion_state, transfer_complete, reserved;
};
_Static_assert(sizeof(struct rm_event) == 96, "response metadata ABI");
#endif
