/* Live integration probe: report controller input at an HTTP parser entry.
 * No request data or credentials are read. Configuration is NOT attribution.
 * Schema 1 row 1: u64 tag followed by three reserved u64 words (all LE).
 */
#include "../config_snapshot.bpf.h"
struct cfg_live_ctx { ls_cfg_u64 arg[12]; };
struct cfg_live_policy { ls_cfg_u64 tag, reserved[3]; };
struct cfg_live_event {
    ls_cfg_u64 instance, revision, tag;
    ls_cfg_u32 schema, available;
};
_Static_assert(sizeof(struct cfg_live_event) == 32, "configuration event ABI");
struct ls_cfg_map_def cfg_live_events __attribute__((section("maps"), used)) = {
    4, 4, 4, 1, 0
};
#ifdef LS_MAP_REUSE_TEST
/* Prime both possible tutorial indices with output storage before revoke. */
struct ls_cfg_map_def cfg_reuse_events __attribute__((section("maps"), used)) = {
    4, 4, 4, 1, 0
};
#endif
static long (*cfg_live_emit)(void *, void *, ls_cfg_u64, void *, ls_cfg_u64) = (void *)25;

__attribute__((section("fentry/http_parse_client_headers"), used))
ls_cfg_u64 config_observe(struct cfg_live_ctx *ctx)
{
    struct cfg_live_event event = {0};
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    if (meta) {
        event.instance = meta->instance;
        event.revision = meta->revision;
        event.schema = meta->schema;
        if (meta->schema == 1 && meta->entries >= 1) {
            struct cfg_live_policy *policy = ls_cfg_get(1);
            if (policy) {
                event.available = 1;
                event.tag = policy->tag;
            }
        }
    }
    cfg_live_emit(ctx, &cfg_live_events, 0, &event, sizeof event);
#ifdef LS_MAP_REUSE_TEST
    cfg_live_emit(ctx, &cfg_reuse_events, 0, &event, sizeof event);
#endif
    return 0;
}
