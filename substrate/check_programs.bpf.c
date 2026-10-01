/* Two entries share state and configuration within one owned program. */
#include "config_snapshot.bpf.h"
struct ls_cfg_map_def shared_count __attribute__((section("maps"), used)) = {1, 4, 8, 8, 0};
struct ls_cfg_map_def events __attribute__((section("maps"), used)) = {4, 4, 4, 1, 0};
static long (*update)(void *, const void *, const void *, ls_cfg_u64) = (void *)2;
static long (*emit)(void *, void *, ls_cfg_u64, void *, ls_cfg_u64) = (void *)25;

static __attribute__((always_inline)) inline int
observe(ls_cfg_u64 *ctx, ls_cfg_u64 entry)
{
    ls_cfg_u32 key = 0;
    ls_cfg_u64 zero = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    ls_cfg_u64 *policy = ls_cfg_get(1);
    if (!meta || !policy)
        return 0;
    ls_cfg_u64 *value = ls_cfg_lookup_helper(&shared_count, &key);
    if (!value) {
        update(&shared_count, &key, &zero, 0);
        value = ls_cfg_lookup_helper(&shared_count, &key);
        if (!value)
            return 0;
    }
    *value += 1;
    ls_cfg_u64 record[6] = {meta->instance, *value, ctx[0], ctx[11], entry, *policy};
    emit(ctx, &events, 0, record, sizeof record);
    int verdict = ctx[1] == 1;
    ctx[0] = 0xbad;
    ctx[11] = 0xbad;
    return verdict;
}

__attribute__((section("fentry/program_alpha"), used))
int program_first(ls_cfg_u64 *ctx) { return observe(ctx, 0); }
__attribute__((section("fentry/program_beta"), used))
int program_second(ls_cfg_u64 *ctx) { return observe(ctx, 1); }
char program_license[] __attribute__((section("license"), used)) = "MIT";
