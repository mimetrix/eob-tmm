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
                   e->magic == RM_MAGIC ? sizeof(struct rm_event2) : sizeof *e));
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
    /* HTTP: two status reads, plus the client TLS walk at code 142:
     * two flow reads, five per node over at most 16 nodes, one flag word,
     * three context reads, session and profile reads. */
    assert(reads <= (slot == 11 ? 312u : 7u + 88u));
    assert(bytes_read <= (slot == 11 ? 9296u : 26u + 600u));
}

/* Authored filter chains for the client TLS walk (TLS-MODE.md). Offsets are
 * those of build 2ab960fa: node above +24, flags +44, private +48, context
 * +64; filter = private - 136; typeid at filter + 64; name at typeid + 0. */
struct tls_filter { unsigned char bytes[136]; uint64_t private_word; };
struct tls_node { _Alignas(64) unsigned char bytes[64 + 1336]; };
static struct tls_filter tls_filters[3];
static uint64_t tls_typeids[3];
static const char *tls_names[3] = {"TCP", "SSL", "HTTP"};
static _Alignas(64) unsigned char tls_session[256], tls_profile[800];

static void tls_put(void *base, unsigned offset, uint64_t value, unsigned size)
{
    memcpy((char *)base + offset, &value, size);
}

static void tls_bits(void *base, unsigned offset, unsigned shift, unsigned width,
        uint32_t value)
{
    uint32_t word;
    memcpy(&word, (char *)base + offset, 4);
    word &= ~(((1u << width) - 1) << shift);
    word |= value << shift;
    memcpy((char *)base + offset, &word, 4);
}

static void tls_types(void)
{
    for (unsigned i = 0; i < 3; i++) {
        tls_typeids[i] = (uintptr_t)tls_names[i];
        /* filter.base.typeid is at filter + 64 */
        uint64_t typeid = (uintptr_t)&tls_typeids[i];
        memcpy(tls_filters[i].bytes + 64, &typeid, 8);
    }
}

/* kinds: 0 TCP, 1 SSL, 2 HTTP. Link nodes bottom to top. */
static void tls_chain(unsigned char *flow, struct tls_node *nodes,
        const unsigned *kinds, unsigned count)
{
    uint64_t bottom = count ? (uintptr_t)nodes[0].bytes : 0;
    memcpy(flow + 80, &bottom, 8);
    for (unsigned i = 0; i < count; i++) {
        memset(nodes[i].bytes, 0, sizeof nodes[i].bytes);
        uint64_t private = (uintptr_t)tls_filters[kinds[i]].bytes + 136;
        tls_put(nodes[i].bytes, 48, private, 8);
        tls_put(nodes[i].bytes, 24, i + 1 < count ? (uintptr_t)nodes[i + 1].bytes : 0, 8);
        tls_bits(nodes[i].bytes, 44, 22, 2, 3); /* f_active, f_ctx */
    }
}

/* Client SSL context: entity=1, hsok, TLS 1.3 / suite 0x1302, pcm, vfy. */
static void tls_pcb(struct tls_node *node, unsigned pcm, unsigned vfy,
        int chain, int session_cert, int retain)
{
    unsigned char *pcb = node->bytes + 64;
    tls_bits(pcb, 12, 0, 1, 1);
    tls_bits(pcb, 12, 26, 1, 1);
    tls_bits(pcb, 4, 15, 2, pcm);
    tls_bits(pcb, 0, 22, 7, vfy);
    tls_put(pcb, 520 + 8, 0x1302, 2);
    tls_bits(pcb, 520 + 12, 8, 4, 6);
    tls_put(pcb, 104, chain ? 0x1000 : 0, 8);
    memset(tls_session, 0, sizeof tls_session);
    memset(tls_profile, 0, sizeof tls_profile);
    tls_put(tls_session, 216, session_cert ? 0x2000 : 0, 8);
    tls_bits(tls_profile, 716, 19, 1, retain ? 1 : 0);
    tls_put(pcb, 80, (uintptr_t)tls_session, 8);
    tls_put(pcb, 72, (uintptr_t)tls_profile, 8);
}

static const struct rm_tls *tls_last(void)
{
    const struct rm_event2 *e = (const void *)records[0];
    assert(frames[0].length == sizeof *e && e->base.abi == 2);
    return &e->tls;
}

static void tls_checks(struct ubpf_vm *v, ubpf_jit_ex_fn fn, unsigned char *flow,
        uint64_t http_ctx[12], unsigned char *status)
{
    static struct tls_node nodes[18];
    const unsigned plain[3] = {0, 2, 2}, ssl[3] = {0, 1, 2};
    const struct rm_tls *t;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *guard = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(guard != MAP_FAILED && !mprotect(guard + page, page, PROT_NONE));
    tls_types();
    flow[36] = 6; flow[37] = 0x41; /* the earlier loop leaves a server side */
    http_ctx[2] = (uintptr_t)flow; http_ctx[3] = (uintptr_t)status;
    status[28] = 2;
    http_ctx[1] = 142;
    /* No SSL node: no_ssl_filter, no detail. */
    tls_chain(flow, nodes, plain, 3);
    call(v, fn, 9, http_ctx);
    t = tls_last();
    assert(t->mode == RM_TLS_NO_FILTER && t->nodes == 3 && !t->bits && !t->reason);
    /* Empty chain is still a complete walk. */
    tls_chain(flow, nodes, plain, 0);
    call(v, fn, 9, http_ctx);
    t = tls_last();
    assert(t->mode == RM_TLS_NO_FILTER && !t->nodes);
    /* Terminated, no certificate requested. */
    tls_chain(flow, nodes, ssl, 3);
    tls_pcb(&nodes[1], 0, 0, 0, 0, 0);
    call(v, fn, 9, http_ctx);
    t = tls_last();
    assert(t->mode == RM_TLS_TERMINATED && t->proto == 6 && t->suite == 0x1302);
    assert(t->pcm == 0 && t->bits == RM_TLS_HSOK);
    /* REQUEST, trusted certificate retained in the session. */
    tls_pcb(&nodes[1], 2, 0, 0, 1, 1);
    call(v, fn, 9, http_ctx);
    t = tls_last();
    assert(t->mode == RM_TLS_TERMINATED && t->pcm == 2 && !t->vfyresult);
    assert(t->bits == (RM_TLS_HSOK | RM_TLS_SESSION_CERT | RM_TLS_RETAIN));
    /* REQUEST, untrusted certificate in the chain: code is kept. */
    tls_pcb(&nodes[1], 2, 20, 1, 0, 1);
    call(v, fn, 9, http_ctx);
    t = tls_last();
    assert(t->vfyresult == 20 && (t->bits & RM_TLS_CHAIN));
    /* REQUEST, no certificate: verify result is still the initial 0. */
    tls_pcb(&nodes[1], 2, 0, 0, 0, 1);
    call(v, fn, 9, http_ctx);
    t = tls_last();
    assert(!t->vfyresult && !(t->bits & (RM_TLS_CHAIN | RM_TLS_SESSION_CERT)));
    /* Handshake not complete, and passthru: not decrypting. */
    tls_bits(nodes[1].bytes + 64, 12, 26, 1, 0);
    call(v, fn, 9, http_ctx);
    assert(tls_last()->mode == RM_TLS_NOT_DECRYPTING);
    tls_bits(nodes[1].bytes + 64, 12, 26, 1, 1);
    tls_bits(nodes[1].bytes + 64, 12, 16, 1, 1);
    call(v, fn, 9, http_ctx);
    assert(tls_last()->mode == RM_TLS_NOT_DECRYPTING);
    tls_bits(nodes[1].bytes + 64, 12, 16, 1, 0);
    /* Server-side SSL entity is never client TLS. */
    tls_bits(nodes[1].bytes + 64, 12, 0, 1, 0);
    call(v, fn, 9, http_ctx);
    t = tls_last();
    assert(t->mode == RM_TLS_UNKNOWN && t->reason == 4 && !t->bits && !t->proto);
    tls_bits(nodes[1].bytes + 64, 12, 0, 1, 1);
    /* Each cleared context flag. */
    for (unsigned bit = 22; bit <= 23; bit++) {
        tls_bits(nodes[1].bytes, 44, bit, 1, 0);
        call(v, fn, 9, http_ctx);
        t = tls_last();
        assert(t->mode == RM_TLS_UNKNOWN && t->reason == 5);
        tls_bits(nodes[1].bytes, 44, bit, 1, 1);
    }
    /* Two SSL nodes. */
    {
        const unsigned twice[4] = {0, 1, 1, 2};
        tls_chain(flow, nodes, twice, 4);
        call(v, fn, 9, http_ctx);
        t = tls_last();
        assert(t->mode == RM_TLS_UNKNOWN && t->reason == 3);
    }
    /* Exactly 16 nodes completes; 17 is the limit; a cycle is the limit. */
    {
        unsigned many[17] = {0};
        tls_chain(flow, nodes, many, 16);
        call(v, fn, 9, http_ctx);
        assert(tls_last()->mode == RM_TLS_NO_FILTER && tls_last()->nodes == 16);
        tls_chain(flow, nodes, many, 17);
        call(v, fn, 9, http_ctx);
        t = tls_last();
        assert(t->mode == RM_TLS_UNKNOWN && t->reason == 2 && t->nodes == 16);
        tls_chain(flow, nodes, many, 2);
        tls_put(nodes[1].bytes, 24, (uintptr_t)nodes[0].bytes, 8);
        call(v, fn, 9, http_ctx);
        assert(tls_last()->mode == RM_TLS_UNKNOWN && tls_last()->reason == 2);
    }
    /* Each unreadable pointer gives read_failed, never a class. */
    {
        uint64_t bad = (uintptr_t)(guard + page);
        tls_chain(flow, nodes, ssl, 3);
        tls_pcb(&nodes[1], 2, 0, 0, 1, 1);
        struct { unsigned char *base; unsigned offset; } cases[] = {
            {flow, 80}, {nodes[0].bytes, 48}, {nodes[0].bytes, 24},
            {nodes[1].bytes + 64, 80}, {nodes[1].bytes + 64, 72},
        };
        for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            uint64_t saved;
            memcpy(&saved, cases[i].base + cases[i].offset, 8);
            tls_put(cases[i].base, cases[i].offset, bad, 8);
            call(v, fn, 9, http_ctx);
            t = tls_last();
            assert(t->mode == RM_TLS_UNKNOWN && t->reason == 1);
            tls_put(cases[i].base, cases[i].offset, saved, 8);
        }
        /* A type pointer and a name pointer at the guard page. */
        uint64_t saved = tls_typeids[1];
        tls_typeids[1] = bad;
        call(v, fn, 9, http_ctx);
        assert(tls_last()->mode == RM_TLS_UNKNOWN && tls_last()->reason == 1);
        tls_typeids[1] = saved;
        /* The SSL node itself at the end of a readable page. */
        unsigned char *edge = guard + page - 48;
        memset(edge, 0, 48);
        tls_put(nodes[0].bytes, 24, (uintptr_t)edge, 8);
        call(v, fn, 9, http_ctx);
        assert(tls_last()->mode == RM_TLS_UNKNOWN && tls_last()->reason == 1);
    }
    /* Unaligned flow; server-side flow and other events read nothing. */
    tls_chain(flow, nodes, ssl, 3);
    tls_pcb(&nodes[1], 0, 0, 0, 0, 0);
    http_ctx[2] = (uintptr_t)flow + 8;
    call(v, fn, 9, http_ctx);
    assert(tls_last()->mode == RM_TLS_UNKNOWN && tls_last()->reason == 6);
    http_ctx[2] = (uintptr_t)flow;
    flow[37] = 0x81;
    call(v, fn, 9, http_ctx);
    assert(tls_last()->mode == RM_TLS_NA && !tls_last()->nodes);
    flow[37] = 0x41;
    for (unsigned i = 0; i < 4; i++) {
        const uint64_t codes[4] = {144, 145, 29, 5};
        http_ctx[1] = codes[i];
        http_ctx[3] = codes[i] == 144 ? (uintptr_t)status : 1;
        call(v, fn, 9, http_ctx);
        t = tls_last();
        assert(t->mode == RM_TLS_NA && !t->nodes && !t->bits);
    }
    /* The walk changes no source byte. */
    {
        unsigned char before[sizeof nodes[1].bytes];
        tls_pcb(&nodes[1], 2, 0, 1, 1, 1);
        memcpy(before, nodes[1].bytes, sizeof before);
        http_ctx[1] = 142; http_ctx[3] = (uintptr_t)status;
        call(v, fn, 9, http_ctx);
        assert(!memcmp(before, nodes[1].bytes, sizeof before));
    }
    memset(flow + 80, 0, 8);
    munmap(guard, page * 2);
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
        /* The existing fixture's flows had no chain: their reading was a
         * complete walk with no SSL filter. Now test authored chains. */
        tls_checks(v[1], fn[1], flow, http_ctx, status);
        for (unsigned i = 0; i < 2; i++) ubpf_destroy(v[i]);
        printf("PASS %s: two contexts, fields, counters, output refusal, bad reads, client TLS\n",
                mode ? "JIT" : "interpreter");
    }
    free(object);
    return 0;
}
