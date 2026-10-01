/* Observed HTTP/1 exchanges. Addresses are private lookup keys, never IDs. */
#ifndef LS_ACTIVITY_GROUP_BPF_H
#define LS_ACTIVITY_GROUP_BPF_H
#include "activity_group_abi.h"
struct ag_ctx { jm_u64 arg[5], result, reserved[6]; };
struct ag_header { jm_u32 magic, abi; jm_u64 instance, revision, run, clock, sequence, failures; };
struct ag_exchange { jm_u64 run, owner, number, state; };
struct ls_cfg_map_def activity_exchanges_v2
    __attribute__((section("maps"), used)) = {1, 8, 32, 128, 0};
static long (*ag_delete)(void *, const void *) = (void *)3;

static __attribute__((noinline)) void activity_forget(jm_u64 client)
{
    jm_u64 zero = 0;
    struct ag_exchange *limit = lookup(&activity_exchanges_v2, &zero);
    if (limit && limit->number && !ag_delete(&activity_exchanges_v2, &client))
        limit->number--;
}

/* status: 0 no active exchange, 1 grouped, 2 unsupported, 3 read failure,
 * 4 overlapping requests, 5 capacity, 6 invalid producer state.
 * phase: 0 none, 1 start, 2 field, 3 end, 4 invalidation. */
static __attribute__((noinline)) void
activity_scope(struct ag_ctx *ctx, const struct ag_header *event,
               struct ag_frame *frame)
{
    jm_u64 flow = ctx->arg[2], client = flow, back = 0;
    jm_u32 code = event->magic == 0x5253504d ? (jm_u32)ctx->arg[1] : 0;
    int http = event->magic == 0x5253504d;
    unsigned short type = 0;
    struct ag_exchange *entry, next = {0};
    if (!event->instance || !event->run || !event->sequence || event->failures) {
        frame->status = 6;
        return;
    }
    frame->invocation = http ? event->sequence : (event->sequence - 1) / 4 + 1;
    if (!ctx->arg[0] || !flow) return;
    frame->status = 2;
    if ((flow & 63) || flow > ~0ull - 80) return;
    frame->status = 3;
    if (read_mem(&type, 2, flow + 36)) return;
    frame->status = 2;
    if ((type & 255) != 6 || ((type >> 8) & 0xc0) == 0xc0) return;
    frame->side = ((type >> 8) & 0xc0) == 0x40 ? 1 :
                  ((type >> 8) & 0xc0) == 0x80 ? 2 : 0;
    if (!frame->side) return;
    if (frame->side == 2) {
        frame->status = 3;
        if (read_mem(&client, 8, flow + 72)) return;
        frame->status = 2;
        if (!client || (client & 63) || client > ~0ull - 80) return;
        frame->status = 3;
        if (read_mem(&type, 2, client + 36) || read_mem(&back, 8, client + 72)) return;
        frame->status = 2;
        if ((type & 255) != 6 || ((type >> 8) & 0xc0) != 0x40 || back != flow) return;
    }
    frame->status = 0;
    entry = lookup(&activity_exchanges_v2, &client);
    if (code == 57 && frame->side == 1) {
        if (entry && entry->run == event->run && entry->number) {
            frame->owner = entry->owner; frame->exchange = entry->number;
            frame->phase = 4; frame->status = 1;
        }
        if (entry) activity_forget(client);
        return;
    }
    if (event->magic == 0x544d4554 && frame->side == 1) {
        /* An overlapping start invalidates the old group. Poison remains until
         * initialization/abort/teardown; a response cannot clear overlap. */
        if (entry && entry->run == event->run && entry->owner == event->instance && entry->state) {
            frame->owner = entry->owner; frame->exchange = entry->number;
            frame->phase = 4; frame->status = 4; entry->state = 3;
            return;
        }
        if (entry) { entry->number = 0; entry->state = 0; }
        if (!entry) {
            /* The host HASH evicts on full. Reserve key zero as an
             * admission count, and stop before an eviction can occur. */
            jm_u64 zero = 0;
            struct ag_exchange *limit = lookup(&activity_exchanges_v2, &zero);
            frame->status = 5;
            if (!limit) {
                if (update(&activity_exchanges_v2, &zero, &next, 0)) return;
                limit = lookup(&activity_exchanges_v2, &zero);
                if (!limit) return;
            }
            if (limit->number >= 127) return;
            limit->number++;
        }
        next.run = event->run; next.owner = event->instance;
        next.number = event->sequence; next.state = 1;
        if (update(&activity_exchanges_v2, &client, &next, 0)) { frame->status = 5; return; }
        frame->owner = next.owner; frame->exchange = next.number;
        frame->phase = 1; frame->status = 1;
        return;
    }
    if (!entry || entry->run != event->run || !entry->number) return;
    if (!http && entry->owner != event->instance) return;
    if (code == 1 || code == 5) {
        frame->owner = entry->owner; frame->exchange = entry->number;
        frame->phase = 4; frame->status = 1;
        activity_forget(client);
        return;
    }
    if (entry->state == 3) { frame->status = 4; return; }
    frame->owner = entry->owner; frame->exchange = entry->number;
    frame->phase = 2; frame->status = 1;
    if (code == 142 && frame->side == 1) {
        unsigned char flags = 0;
        frame->phase = 4; frame->status = 2;
        if (entry->state == 1 && ctx->arg[3] && ctx->arg[3] <= ~0ull - 29) {
            frame->status = 3;
            if (!read_mem(&flags, 1, ctx->arg[3] + 28)) {
                frame->status = 2;
                /* is_trailer=0, is_request=1 in http_parse_info. */
                if ((flags & 3) == 2) {
                    frame->phase = 2; frame->status = 1;
                    entry->state = 2;
                    return;
                }
            }
        }
        entry->state = 3;
        return;
    }
    if (frame->side == 2 && entry->state != 2) {
        frame->owner = frame->exchange = 0;
        frame->phase = 0; frame->status = 0;
        return;
    }
    if (code == 29 && frame->side == 1) {
        frame->phase = 3;
        activity_forget(client);
    }
}

static __attribute__((noinline)) long
activity_emit(void *ctx, void *map, jm_u64 flags, void *payload, jm_u64 length)
{
    struct ag_frame frame = {0};
    /* Every reader supplies an eight-byte-aligned event. Preserve that fact
     * across this function boundary instead of expanding byte-wise copies. */
    payload = __builtin_assume_aligned(payload, 8);
    frame.magic = AG_MAGIC; frame.abi = 2; frame.length = length;
    activity_scope(ctx, payload, &frame);
    if (length == 144) __builtin_memcpy(frame.payload, payload, 144);
    else if (length == 104) __builtin_memcpy(frame.payload, payload, 104);
    else if (length == 96) __builtin_memcpy(frame.payload, payload, 96);
    else return -1;
    return emit(ctx, map, flags, &frame, 48 + length);
}
#endif
