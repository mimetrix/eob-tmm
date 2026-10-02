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

/* ABI 2 adds the client connection's TLS state (TLS-MODE.md). Layout facts
 * are from build 2ab960fa; they are not a portable TMM ABI.
 *
 * mode: 0 not applicable (not the client-side request-header event),
 *       1 terminated, 2 SSL filter present but not decrypting,
 *       3 no SSL filter in the chain, 4 unknown.
 * reason (mode 4): 1 read failure, 2 walk limit, 3 second SSL node,
 *       4 server-side entity, 5 inactive or missing context,
 *       6 invalid flow address. */
#define RM_TLS_NA 0u
#define RM_TLS_TERMINATED 1u
#define RM_TLS_NOT_DECRYPTING 2u
#define RM_TLS_NO_FILTER 3u
#define RM_TLS_UNKNOWN 4u
#define RM_TLS_NODES_MAX 16u
/* bits */
#define RM_TLS_HSOK 1u
#define RM_TLS_PASSTHRU 2u
#define RM_TLS_CHAIN 4u
#define RM_TLS_SESSION_CERT 8u
#define RM_TLS_RETAIN 16u
#define RM_TLS_ST_RESUME 32u
#define RM_TLS_SS_RESUME 64u
#define RM_TLS_ALLOW_NONSSL 128u
struct rm_tls {
    jm_u32 mode, reason, nodes, bits;
    jm_u32 proto, suite, pcm, vfyresult;
};
_Static_assert(sizeof(struct rm_tls) == 32, "TLS block");
struct rm_event2 {
    struct rm_event base;
    struct rm_tls tls;
};
_Static_assert(sizeof(struct rm_event2) == 128, "response metadata ABI 2");
#endif
