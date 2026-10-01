/* Two VMs from the same ELF, alternating contexts and shared registry. */
#define LS_ACTIVITY_TEST
#define main message_id_standalone_main
#include "check_message_id.c"
#undef main
#include "surfaces/operation_target_abi.h"
#include "surfaces/id_flow_abi.h"
#include "surfaces/reply_metadata_abi.h"
#include "surfaces/response_metadata_abi.h"
#include "surfaces/activity_group_abi.h"
#include "ls_vm.h"

static unsigned active_slot, emitted;
static uint64_t sequences[2], failures[2];
static uint64_t instances[2];
static _Alignas(8) unsigned char records[4][144];
static struct ag_frame frames[4];

int ls_tp_publish_raw(int slot, const void *data, unsigned long size)
{
    const struct ag_frame *frame = data;
    assert(frame->magic == AG_MAGIC && frame->abi == 2 && size == 48 + frame->length);
    const struct jm_event *e = (const void *)frame->payload;
    unsigned which = slot == 11 ? 0 : 1;
    const unsigned magics[4] = {TM_MAGIC, OT_MAGIC, IF_MAGIC, RP_MAGIC};
    assert(slot == (int)active_slot && emitted < (slot == 11 ? 4u : 1u));
    assert(e->magic == (slot == 11 ? magics[emitted] : RM_MAGIC));
    assert(frame->length == (e->magic == RP_MAGIC ? sizeof(struct rp_event) :
                   e->magic == RM_MAGIC ? sizeof(struct rm_event) : sizeof *e));
    assert(e->instance == instances[which] && e->revision == 1 && e->run == 123);
    assert(e->sequence == ++sequences[which]);
    assert(e->output_failures == failures[which]);
    memset(&frames[emitted], 0, sizeof frames[emitted]);
    memcpy(&frames[emitted], data, size);
    memcpy(records[emitted++], frame->payload, frame->length);
    printf("RECORD %d ", slot);
    for (unsigned long i = 0; i < size; i++)
        printf("%02x", ((const unsigned char *)data)[i]);
    puts("");
    if (refuse) failures[which]++;
    return refuse ? -1 : 0;
}

static void call(struct ubpf_vm *v, ubpf_jit_ex_fn fn, unsigned slot,
        uint64_t ctx[12])
{
    unsigned char stack[4096] = {0};
    uint64_t saved[12] = {0}, ret = 99;
    memcpy(saved, ctx, sizeof saved);
    active_slot = slot; emitted = reads = bytes_read = 0;
    g_ls_cur_slot = slot; ls_config_begin(&g_ls_config_view, slot);
    if (mode) ret = fn(ctx, sizeof saved, stack, sizeof stack);
    else assert(!ubpf_exec_ex(v, ctx, sizeof saved, &ret, stack, sizeof stack));
    g_ls_config_view.active = 0; g_ls_cur_slot = -1;
    assert(!ret && !memcmp(saved, ctx, sizeof saved));
    assert(emitted == (slot == 11 ? 4u : 1u));
    assert(reads <= (slot == 11 ? 312u : 7u));
    assert(bytes_read <= (slot == 11 ? 9296u : 26u));
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    FILE *f = fopen(argv[1], "rb");
    assert(f && !fseek(f, 0, SEEK_END));
    long size = ftell(f);
    assert(size > 0 && !fseek(f, 0, SEEK_SET));
    void *object = malloc(size);
    assert(object && fread(object, 1, size, f) == (size_t)size);
    fclose(f);
    g_ls_config.session = 42;
    assert(ls_ranges_current(1));
    for (mode = 0; mode < 2; mode++) {
        struct ubpf_vm *v[2] = {0};
        ubpf_jit_ex_fn fn[2] = {0};
        const char *functions[2] = {"activity_json", "activity_http"};
        uint64_t scb[12] = {0}, json_ctx[12] = {0}, http_ctx[12] = {0};
        _Alignas(64) unsigned char flow[128] = {0}, peer[128] = {0};
        _Alignas(64) unsigned char other[128] = {0}, other_peer[128] = {0};
        unsigned char status[40] = {0};
        uint32_t code = 200;
        assert(!ls_map_reset_shapes());
        memset(sequences, 0, sizeof sequences);
        memset(failures, 0, sizeof failures);
        for (unsigned i = 0; i < 2; i++) {
            char *error = NULL;
            unsigned slot = i ? 9 : 11;
            struct ls_config_request r = {0};
            uint64_t run = 123;
            r.abi = r.schema = r.entries = 1; r.session = 42;
            r.instance = ls_config_new_instance(&g_ls_config, slot);
            instances[i] = r.instance; r.revision = 1;
            memset(r.program_sha256, 7, 32); memcpy(r.rows, &run, 8);
            g_ls_config.loading = r.instance;
            v[i] = ubpf_create(); assert(v[i] && !ls_map_glue_install(v[i]));
            assert(!ubpf_register(v[i], 4, "tracked_read", tracked_read));
            int rc = ubpf_load_elf_ex(v[i], object, size, functions[i], &error);
            if (rc) fprintf(stderr, "%s\n", error);
            assert(!rc);
            ubpf_set_jit_code_size(v[i], LS_JIT_CODE_MAX);
            fn[i] = ubpf_compile_ex(v[i], &error, ExtendedJitMode);
            if (!fn[i]) fprintf(stderr, "%s\n", error);
            assert(fn[i]);
            assert(!ls_config_bind(&g_ls_config, slot, r.instance, r.program_sha256));
            assert(!ls_config_publish(&g_ls_config, slot, &r, 112));
        }
        g_ls_config.loading = 0;
        flow[36] = peer[36] = other[36] = other_peer[36] = 6;
        flow[37] = other[37] = 0x41;
        peer[37] = other_peer[37] = 0x81;
        uintptr_t address = (uintptr_t)peer; memcpy(flow + 72, &address, 8);
        address = (uintptr_t)flow; memcpy(peer + 72, &address, 8);
        address = (uintptr_t)other_peer; memcpy(other + 72, &address, 8);
        address = (uintptr_t)other; memcpy(other_peer + 72, &address, 8);
        scb[3] = (uintptr_t)&cache; scb[11] = 0x24;
        json_ctx[0] = 1; json_ctx[1] = (uintptr_t)scb; json_ctx[2] = (uintptr_t)flow;
        http_ctx[0] = 1; http_ctx[1] = 144;
        http_ctx[2] = (uintptr_t)flow; http_ctx[3] = (uintptr_t)status;
        memcpy(status + 36, &code, 4);
        fixture("{\"method\":\"tools/call\",\"params\":{\"name\":\"sum\"},\"id\":\"same\"}");
        json_ctx[2] = (uintptr_t)peer;
        call(v[0], fn[0], 11, json_ctx);
        assert(!frames[0].exchange); /* Late attachment never invents a start. */
        json_ctx[2] = (uintptr_t)flow;
        call(v[0], fn[0], 11, json_ctx);
        uint64_t first = frames[0].exchange;
        assert(first && frames[0].phase == 1 && frames[0].owner == instances[0]);
        json_ctx[2] = (uintptr_t)peer;
        call(v[0], fn[0], 11, json_ctx);
        assert(!frames[0].exchange); /* No server association before headers. */
        http_ctx[1] = 142; status[28] = 2;
        call(v[1], fn[1], 9, http_ctx);
        assert(frames[0].phase == 2 && frames[0].exchange == first);
        json_ctx[2] = (uintptr_t)other;
        call(v[0], fn[0], 11, json_ctx);
        uint64_t second = frames[0].exchange;
        assert(second && second != first);
        http_ctx[2] = (uintptr_t)other;
        call(v[1], fn[1], 9, http_ctx);
        json_ctx[2] = (uintptr_t)other_peer;
        call(v[0], fn[0], 11, json_ctx);
        for (unsigned j = 0; j < 4; j++) {
            assert(frames[j].exchange == second && frames[j].side == 2);
            assert(frames[j].invocation == frames[0].invocation);
        }
        json_ctx[2] = (uintptr_t)peer;
        call(v[0], fn[0], 11, json_ctx);
        assert(frames[0].exchange == first);
        /* A wrong peer cannot borrow another client's exchange. */
        address = (uintptr_t)other; memcpy(peer + 72, &address, 8);
        call(v[0], fn[0], 11, json_ctx);
        assert(!frames[0].exchange && frames[0].status == 2);
        address = (uintptr_t)flow; memcpy(peer + 72, &address, 8);
        http_ctx[2] = (uintptr_t)flow; http_ctx[1] = 29; http_ctx[3] = 1;
        call(v[1], fn[1], 9, http_ctx);
        assert(frames[0].phase == 3 && frames[0].exchange == first);
        call(v[0], fn[0], 11, json_ctx);
        assert(!frames[0].exchange);
        /* Keep-alive gets a new number; overlapping starts poison the group. */
        http_ctx[1] = 142; http_ctx[3] = (uintptr_t)status;
        json_ctx[2] = (uintptr_t)flow;
        call(v[0], fn[0], 11, json_ctx);
        assert(frames[0].exchange > second);
        call(v[0], fn[0], 11, json_ctx);
        assert(frames[0].phase == 4 && frames[0].status == 4);
        json_ctx[2] = (uintptr_t)peer;
        call(v[0], fn[0], 11, json_ctx);
        assert(!frames[0].exchange && frames[0].status == 4);
        http_ctx[1] = 57; call(v[1], fn[1], 9, http_ctx);
        json_ctx[2] = (uintptr_t)flow;
        call(v[0], fn[0], 11, json_ctx);
        assert(frames[0].phase == 1 && frames[0].exchange > second);
        http_ctx[1] = 5; call(v[1], fn[1], 9, http_ctx);
        assert(frames[0].phase == 4);
        json_ctx[2] = (uintptr_t)peer;
        call(v[0], fn[0], 11, json_ctx);
        assert(!frames[0].exchange);
        /* Invalid request metadata poisons a started group. */
        json_ctx[2] = (uintptr_t)flow;
        call(v[0], fn[0], 11, json_ctx);
        http_ctx[1] = 142; http_ctx[3] = 7;
        call(v[1], fn[1], 9, http_ctx);
        assert(frames[0].phase == 4 && frames[0].status == 3);
        json_ctx[2] = (uintptr_t)peer;
        call(v[0], fn[0], 11, json_ctx);
        assert(!frames[0].exchange);
        http_ctx[1] = 57; call(v[1], fn[1], 9, http_ctx);
        http_ctx[3] = (uintptr_t)status; status[28] = 0;
        http_ctx[1] = 144;
        json_ctx[2] = (uintptr_t)flow;
        const char *texts[] = {
            "{\"method\":\"tools/call\",\"params\":{\"name\":\"sum\"},\"id\":\"one\"}",
            "{\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///one\"},\"id\":9007199254740993}",
            "{\"id\":\"one\",\"result\":{\"isError\":false}}",
            "{\"id\":\"one\",\"error\":{\"code\":-32601}}",
            "{\"id\":\"first\",\"id\":\"second\"}",
            "{}"
        };
        for (unsigned i = 0; i < sizeof texts / sizeof texts[0]; i++) {
            fixture(texts[i]);
            flow[37] = i < 2 ? 0x41 : 0x81;
            call(v[0], fn[0], 11, json_ctx);
            if (i < 2) {
                const struct jm_event *method = (const void *)records[0];
                const struct jm_event *target = (const void *)records[1];
                const struct jm_event *id = (const void *)records[2];
                assert(method->status == JM_COMPLETE && target->status == JM_COMPLETE);
                assert(id->status == JM_COMPLETE);
                assert(!memcmp(method->value, i ? "resources/read" : "tools/call", i ? 14 : 10));
                assert(!memcmp(target->value, i ? "file:///one" : "sum", i ? 11 : 3));
                assert((id->flags >> IF_SIDE_SHIFT & 3) == 1);
            }
            call(v[1], fn[1], 9, http_ctx);
            assert(((const struct rm_event *)(const void *)records[0])->http_status == 200);
        }
        /* Exhaust the bounded table; failure must not borrow an old key. */
        static _Alignas(64) unsigned char many[129][128];
        unsigned admitted = 0, full = 0;
        for (unsigned i = 0; i < 129; i++) {
            many[i][36] = 6; many[i][37] = 0x41;
            json_ctx[2] = (uintptr_t)many[i];
            call(v[0], fn[0], 11, json_ctx);
            if (frames[0].status == 5) {
                full++;
                for (unsigned j = 0; j < 4; j++) assert(!frames[j].exchange);
            } else {
                admitted++;
                assert(frames[0].phase == 1 && frames[0].exchange);
            }
        }
        assert(admitted == 125 && full == 4);
        assert(g_ls_maps->m[3].evictions == 0);
        http_ctx[2] = (uintptr_t)many[0]; http_ctx[1] = 29; http_ctx[3] = 1;
        call(v[1], fn[1], 9, http_ctx);
        json_ctx[2] = (uintptr_t)many[128];
        call(v[0], fn[0], 11, json_ctx);
        assert(frames[0].phase == 1 && frames[0].exchange);
        assert(g_ls_maps->m[3].evictions == 0);
        http_ctx[2] = (uintptr_t)flow; http_ctx[1] = 144;
        http_ctx[3] = (uintptr_t)status;
        json_ctx[2] = (uintptr_t)flow;
        /* A failed output advances failure accounting without stopping readers.
         * The other hook's state remains intact. */
        refuse = 1; call(v[0], fn[0], 11, json_ctx);
        refuse = 0; call(v[1], fn[1], 9, http_ctx);
        call(v[0], fn[0], 11, json_ctx);
        assert(failures[0] == 4 && !failures[1]);
        http_ctx[1] = 145; http_ctx[3] = 0;
        call(v[1], fn[1], 9, http_ctx);
        assert(((const struct rm_event *)(const void *)records[0])->completion_state == RM_COMPLETE);
        assert(!((const struct rm_event *)(const void *)records[0])->transfer_complete);
        /* Same malformed pointer is guarded independently by all four readers. */
        json_ctx[1] = 7; call(v[0], fn[0], 11, json_ctx);
        for (unsigned i = 0; i < 2; i++) ubpf_destroy(v[i]);
        printf("PASS %s: two contexts, fields, counters, output refusal, bad reads\n",
                mode ? "JIT" : "interpreter");
    }
    free(object);
    return 0;
}
