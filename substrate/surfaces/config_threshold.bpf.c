/* Controller input -> bounded decision -> existing event output.
 * Fixture hook: arg0 is a scalar observation, NOT a TMM pointer to dereference.
 * Schema 1 row 1: u64 threshold, u64 enabled, two reserved u64 (all LE).
 * Observe-only: this example never requests a host enforcement action.
 */
#include "../config_snapshot.bpf.h"
struct cfg_ctx { ls_cfg_u64 arg[12]; };
struct cfg_policy { ls_cfg_u64 threshold, enabled, reserved[2]; };
struct cfg_event {
    ls_cfg_u64 revision, instance, observation, threshold;
    ls_cfg_u32 matched, schema;
};
struct ls_cfg_map_def cfg_events __attribute__((section("maps"), used)) = {
    4, 4, 4, 1, 0
};
static long (*cfg_emit)(void *, void *, ls_cfg_u64, void *, ls_cfg_u64) = (void *)25;

__attribute__((section("fentry/config_fixture"), used))
ls_cfg_u64 config_threshold(struct cfg_ctx *ctx)
{
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    if (!meta || meta->schema != 1 || meta->entries < 1)
        return 0;
    struct cfg_policy *policy = ls_cfg_get(1);
    if (!policy || policy->enabled != 1)
        return 0;
    struct cfg_event event = {
        meta->revision, meta->instance, ctx->arg[0], policy->threshold,
        ctx->arg[0] >= policy->threshold, 1
    };
    cfg_emit(ctx, &cfg_events, 0, &event, sizeof event);
    /* Harness publishes DURING emit. A subsequent lookup must retain the same
     * revision. Return 1 is a consistency-test failure, not a mitigation. */
    struct ls_cfg_meta *again = ls_cfg_get(0);
    return !again || again->revision != event.revision;
}
