/* One ELF, two entry contexts. Readers retain their bounded wire formats. */
#include "../config_snapshot.bpf.h"
#include "token_method_abi.h"

struct ls_cfg_map_def activity_json_state
    __attribute__((section("maps"), used)) = {1, 4, 32, 1, 0};
struct ls_cfg_map_def activity_http_state
    __attribute__((section("maps"), used)) = {1, 4, 32, 1, 0};
struct ls_cfg_map_def metadata_events
    __attribute__((section("maps"), used)) = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, jm_u64) = (void *)2;
static long (*read_mem)(void *, jm_u64, jm_u64) = (void *)4;
static jm_u64 (*clock_ns)(void) = (void *)5;
static long (*emit)(void *, void *, jm_u64, void *, jm_u64) = (void *)25;

#include "activity_group.bpf.h"
#define emit activity_emit

/* Compile the same readers, without their standalone maps or entry sections.
 * All four JSON readers use the same instance and advance the same counter.
 * HTTP has a private map: alternating hooks must not reset either counter. */
#define LS_ACTIVITY_EMBED
#define metadata_token_state activity_json_state
#define read_field tm_read_field
#define read_bytes tm_read_bytes
#define extract tm_extract
#include "token_method.bpf.c"
#undef metadata_token_state
#undef read_field
#undef read_bytes
#undef extract

#define operation_target_state activity_json_state
#define field ot_field
#define bytes ot_bytes
#define token ot_token
#define member ot_member
#define extract ot_extract
#include "operation_target.bpf.c"
#undef operation_target_state
#undef field
#undef bytes
#undef token
#undef member
#undef extract

#define reply_metadata_state activity_json_state
#define field rp_field
#define bytes rp_bytes
#define token rp_token
#define scan rp_scan
#define value rp_value
#define extract rp_extract
#include "reply_metadata.bpf.c"
#undef reply_metadata_state
#undef field
#undef bytes
#undef token
#undef scan
#undef value
#undef extract

#define id_flow_state activity_json_state
#define field mi_field
#define bytes mi_bytes
#define token mi_token
#define member mi_member
#define number mi_number
#define extract mi_extract
#include "id_flow.bpf.c"
#undef id_flow_state
#undef field
#undef bytes
#undef token
#undef member
#undef number
#undef extract

#define response_metadata_state activity_http_state
#define read_field rm_read_field
#define extract rm_extract
#include "response_metadata.bpf.c"
#undef response_metadata_state
#undef read_field
#undef extract
#undef LS_ACTIVITY_EMBED
#undef emit

__attribute__((section("fentry/json_filter_handle_json_complete"), used))
jm_u64 activity_json(void *ctx)
{
    token_method(ctx);
    operation_target(ctx);
    message_id(ctx);
    reply_metadata(ctx);
    return 0;
}

__attribute__((section("fentry/hud_aimcp_handler"), used))
jm_u64 activity_http(void *ctx)
{
    return response_metadata(ctx);
}
