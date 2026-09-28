/* Observed parser intervals, not authenticated request/connection identities. */
#include "../config_snapshot.bpf.h"
typedef ls_cfg_u32 u32;
typedef ls_cfg_u64 u64;

#if LIFE_KIND == 1
#define SECTION "fentry/http_parse_ctx_init"
#elif LIFE_KIND == 2
#define SECTION "fexit/http_parse_client_headers"
#elif LIFE_KIND == 3
#define SECTION "fentry/http_parse_ctx_fini"
#else
#error "select LIFE_KIND 1, 2 or 3"
#endif

struct life_ctx { u64 arg[5], result, reserved[6]; };
struct life_state { u64 run, calls, births, failures; };
struct life_object { u64 run, lifetime, attempt, state; };
struct life_event {
    u32 magic, abi;
    u64 run, sequence, lifetime, attempt, value, failures;
    u32 kind, flags;
};
_Static_assert(sizeof(struct life_event) == 64, "event ABI");
_Static_assert(sizeof(struct life_ctx) == 96, "context ABI");
_Static_assert(sizeof(struct life_object) == 32, "map value ceiling");
struct ls_cfg_map_def life_state __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
struct ls_cfg_map_def life_objects __attribute__((section("maps"), used))
    = {1, 8, 32, 256, 0};
struct ls_cfg_map_def life_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static long (*emit)(void *, void *, u64, void *, u64) = (void *)25;

#define NO_CONFIG 1u
#define MAP_FAILED 2u
#define CAPACITY 4u
#define OVERFLOW 8u
#define NULL_ADDRESS 16u
#define NO_BIRTH 32u
#define AFTER_END 64u
#define DUP_BIRTH 128u
#define PARTIAL_END 256u
#define PARSE_ERROR 512u
#define ACTIVE 1ull
#define PARTIAL 2ull
#define BROKEN 4ull

__attribute__((section(SECTION), used))
u64 parser_lifetime(struct life_ctx *ctx)
{
    struct life_event event = {0};
    struct life_state fresh = {0};
    struct life_object next = {0};
    struct life_state *state = 0;
    struct life_object *object = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    u64 *row = ls_cfg_get(1);
    u64 key = ctx->arg[0];
    u32 zero = 0;
    event.magic = 0x4c494645u;
    event.abi = 1;
    event.kind = LIFE_KIND;
#if LIFE_KIND == 2
    event.value = ctx->result;
#endif
    if (!meta || meta->schema != 1 || meta->entries != 1 || !row ||
            !row[0] || row[1] || row[2] || row[3]) {
        event.flags = NO_CONFIG;
        goto out;
    }
    event.run = row[0];
    state = lookup(&life_state, &zero);
    if (!state || state->run != event.run) {
        fresh.run = event.run;
        if (update(&life_state, &zero, &fresh, 0)) {
            event.flags = MAP_FAILED;
            state = 0;
            goto out;
        }
        state = lookup(&life_state, &zero);
    }
    if (!state) {
        event.flags = MAP_FAILED;
        goto out;
    }
    event.failures = state->failures;
    if (state->calls == ~0ull) {
        event.flags = OVERFLOW;
        goto out;
    }
    event.sequence = ++state->calls;
    if (!key) {
        event.flags = NULL_ADDRESS;
        goto out;
    }
    object = lookup(&life_objects, &key);
#if LIFE_KIND == 1
    /* At most 256 insertions per run: never reach the map's eviction path.
     * Do not reuse this run token with retained state from an earlier run. */
    if (object && object->run == event.run) {
        event.value = object->lifetime;
        if (object->state & ACTIVE)
            event.flags |= DUP_BIRTH;
        object->state = 0;
    }
    if (state->births >= 256) {
        event.flags |= CAPACITY;
        goto out;
    }
    next.run = event.run;
    next.lifetime = ++state->births;
    next.state = ACTIVE;
    if (update(&life_objects, &key, &next, 0)) {
        event.flags |= MAP_FAILED;
        goto out;
    }
    event.lifetime = next.lifetime;
#else
    (void)next;
    if (!object || object->run != event.run) {
        event.flags = NO_BIRTH;
        goto out;
    }
    if (!(object->state & ACTIVE)) {
        event.flags = AFTER_END;
        goto out;
    }
    event.lifetime = object->lifetime;
#if LIFE_KIND == 2
    if (object->state & BROKEN) {
        event.flags = PARSE_ERROR;
        goto out;
    }
    if (!(object->state & PARTIAL)) {
        if (object->attempt == ~0ull) {
            event.flags = OVERFLOW;
            goto out;
        }
        object->attempt++;
    }
    if (ctx->result == 17)
        object->state |= PARTIAL;
    else if (ctx->result == 0)
        object->state &= ~PARTIAL;
    else {
        object->state |= BROKEN;
        event.flags = PARSE_ERROR;
    }
#else
    if (object->state & PARTIAL)
        event.flags = PARTIAL_END;
    object->state = 0;
#endif
    event.attempt = object->attempt;
#endif
out:
    if (emit(ctx, &life_events, 0, &event, sizeof event) && state &&
            state->failures != ~0ull)
        state->failures++;
    return 0;
}
