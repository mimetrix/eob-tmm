/* Bounded fixture header extraction. Values are candidates, never credentials. */
#include "../config_snapshot.bpf.h"
typedef ls_cfg_u32 u32;
typedef ls_cfg_u64 u64;
typedef unsigned char u8;

struct context { u64 arg[5], result, reserved[6]; };
struct object { u64 run, lifetime, attempt, state; };
struct counter { u64 run, calls, births, failures; };
struct progress {
    u64 lifetime, attempt;
    u32 total, flags;
    u8 mode, n, match, seen;
    u32 path;
};
struct bytes { u8 data[32]; };
struct event {
    u32 magic, abi;
    u64 run, sequence, lifetime, attempt, failures;
    u32 flags, path, total, reserved;
    u8 nonce[32];
};
_Static_assert(sizeof(struct event) == 96, "wire ABI");
_Static_assert(sizeof(struct progress) == 32, "map ceiling");
struct ls_cfg_map_def life_objects __attribute__((section("maps"), used))
    = {1, 8, 32, 256, 0};
struct ls_cfg_map_def life_state __attribute__((section("maps"), used))
    = {1, 4, 32, 1, 0};
/* Two rows per lifetime; admit only lifetimes 1..127 in a fresh registry. */
struct ls_cfg_map_def candidate_store __attribute__((section("maps"), used))
    = {1, 8, 32, 256, 0};
struct ls_cfg_map_def life_events __attribute__((section("maps"), used))
    = {4, 4, 4, 1, 0};
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static long (*read_bytes)(void *, u32, const void *) = (void *)4;
static long (*emit)(void *, void *, u64, void *, u64) = (void *)25;

#define COMPLETE 1u
#define CONFIG 2u
#define NO_BIRTH 4u
#define UNSUPPORTED 8u
#define READ_FAILED 16u
#define MAP_FAILED 32u
#define INVALID 64u
#define DUPLICATE 128u
#define LIMIT 256u
#define MISSING 512u
#define OVERFLOW 1024u
enum mode { FIRST, NAME, SPACE, VALUE, VALUE_LF, SKIP, SKIP_LF,
            END_LF, DONE, BAD };

static __attribute__((always_inline)) inline void
consume(struct progress *s, struct bytes *b, u8 c)
{
    u32 n = s->n;
    switch (s->mode) {
    case FIRST:
        if ((!n && c != 'P') || n >= 31) {
            s->flags = UNSUPPORTED;
            break;
        }
        if (c != '\n') {
            b->data[n & 31] = c;
            s->n = n + 1;
            return;
        }
        if (n == 19 && !__builtin_memcmp(b->data,
                    "POST /mcp HTTP/1.1\r", 19))
            s->path = 1;
        else if (n == 19 && !__builtin_memcmp(b->data,
                    "POST /a2a HTTP/1.1\r", 19))
            s->path = 2;
        else if (n == 24 && !__builtin_memcmp(b->data,
                    "POST /delegate HTTP/1.1\r", 24))
            s->path = 3;
        else {
            s->flags = UNSUPPORTED;
            break;
        }
        __builtin_memset(b->data, 0, 32);
        s->mode = NAME;
        s->n = 0;
        s->match = 1;
        return;
    case NAME:
        if (!n && c == '\r') {
            s->mode = END_LF;
            return;
        }
        if (c == ':' && n == 13 && s->match) {
            if (s->seen) {
                s->flags = DUPLICATE;
                break;
            }
            s->seen = 1;
            s->mode = SPACE;
            return;
        }
        if (n >= 13 || (c | 32) != (u8)(n < 8 ?
                    0x2d666f6f72702d78ull >> ((n & 7) * 8) :
                    0x65636e6f6eull >> (((n - 8) & 7) * 8))) {
            s->mode = c == '\r' ? SKIP_LF : SKIP;
            if (c == '\n') s->flags = UNSUPPORTED;
        } else {
            s->n = n + 1;
        }
        return;
    case SPACE:
        if (c != ' ') { s->flags = INVALID; break; }
        s->mode = VALUE;
        s->n = 0;
        return;
    case VALUE:
        if (n == 32 && c == '\r') {
            s->mode = VALUE_LF;
            return;
        }
        if (n >= 32 || !((c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            s->flags = INVALID;
            break;
        }
        b->data[n & 31] = c;
        s->n = n + 1;
        return;
    case SKIP:
        if (c == '\r') s->mode = SKIP_LF;
        else if (c == '\n') s->flags = UNSUPPORTED;
        return;
    case VALUE_LF:
    case SKIP_LF:
        if (c != '\n') { s->flags = UNSUPPORTED; break; }
        s->mode = NAME;
        s->n = 0;
        s->match = 1;
        return;
    case END_LF:
        if (c != '\n') { s->flags = UNSUPPORTED; break; }
        s->mode = DONE;
        s->flags = s->seen ? COMPLETE : MISSING;
        return;
    default:
        s->flags = UNSUPPORTED;
        break;
    }
    s->mode = BAD;
}

__attribute__((section("fentry/http_parse_headers"), used))
u64 request_candidate(struct context *ctx)
{
    struct event e = {0};
    struct counter fresh = {0}, *count = 0;
    struct progress initial = {0}, *s = 0;
    struct bytes empty = {0}, *b = 0;
    struct object *object = 0;
    struct ls_cfg_meta *meta = ls_cfg_get(0);
    u64 *config = ls_cfg_get(1);
    u64 address = ctx->arg[0], attempt = 0, state_key = 0, bytes_key = 0;
    u32 zero = 0, length = (u32)ctx->arg[3];
    e.magic = 0x43414e44;
    e.abi = 1;
    if (!meta || meta->schema != 1 || meta->entries != 1 || !config ||
            !config[0] || config[1] || config[2] || config[3]) {
        e.flags = CONFIG;
        goto out;
    }
    e.run = config[0];
    count = lookup(&life_state, &zero);
    if (!count) {
        fresh.run = e.run;
        if (update(&life_state, &zero, &fresh, 0)) {
            e.flags = MAP_FAILED;
            goto out;
        }
        count = lookup(&life_state, &zero);
    }
    if (!count) { e.flags = MAP_FAILED; goto out; }
    if (count->run != e.run) { e.flags = CONFIG; goto out; }
    e.failures = count->failures;
    if (count->calls == ~0ull) { e.flags = OVERFLOW; goto out; }
    e.sequence = ++count->calls;
    object = lookup(&life_objects, &address);
    if (!address || !object || object->run != e.run ||
            !(object->state & 1) || (object->state & 4)) {
        e.flags = NO_BIRTH;
        goto out;
    }
    e.lifetime = object->lifetime;
    if (!object->lifetime || object->lifetime > 127) {
        e.flags = LIMIT;
        goto out;
    }
    state_key = object->lifetime * 2;
    bytes_key = state_key + 1;
    attempt = object->attempt;
    if (!(object->state & 2)) {
        if (attempt == ~0ull) { e.flags = OVERFLOW; goto out; }
        attempt++;
    }
    e.attempt = attempt;
    s = lookup(&candidate_store, &state_key);
    if (!s || s->lifetime != object->lifetime || s->attempt != attempt) {
        initial.lifetime = object->lifetime;
        initial.attempt = attempt;
        if (update(&candidate_store, &state_key, &initial, 0) ||
                update(&candidate_store, &bytes_key, &empty, 0)) {
            e.flags = MAP_FAILED;
            goto out;
        }
        s = lookup(&candidate_store, &state_key);
    }
    b = lookup(&candidate_store, &bytes_key);
    if (!s || !b) { e.flags = MAP_FAILED; goto out; }
    for (u32 i = 0; i < 512; i++) {
        u8 c = 0;
        if (s->mode == DONE || s->mode == BAD || s->flags || i >= length)
            break;
        if (s->total >= 512) { s->flags = LIMIT; break; }
        if (ctx->arg[2] > ~0ull - 512 ||
                read_bytes(&c, 1, (void *)(ctx->arg[2] + i))) {
            s->flags = READ_FAILED;
            break;
        }
        s->total++;
        consume(s, b, c);
    }
    if (s->total >= 512 && s->mode != DONE && !s->flags)
        s->flags = LIMIT;
    e.flags = s->flags;
    e.total = s->total;
    if (s->mode == DONE && s->flags == COMPLETE) {
        e.path = s->path;
        __builtin_memcpy(e.nonce, b->data, 32);
    }
out:
    if (emit(ctx, &life_events, 0, &e, sizeof e) && count &&
            count->failures != ~0ull)
        count->failures++;
    return 0;
}
