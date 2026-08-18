/* ls_drain --- the tracepoint's drain agent.
 *
 * Maps the shared segment, consumes records, writes them to stdout as JSON
 * lines, and acknowledges them so the rings stay open. That is the whole job.
 *
 * THE GOVERNING CONSTRAINT: TMM MUST NOT DEPEND ON THIS PROGRAM. Not on it
 * running, not on it keeping up, not on it exiting cleanly. Everything below
 * follows from that, and check_drain.c asserts it rather than trusting it:
 *
 *   - The producer never blocks on a consumer. ls_ring_emit on a full STREAM
 *     ring returns 0 and increments `drops`. There is no path in which TMM
 *     waits, retries, or errors because of anything here.
 *   - This agent NEVER writes to the ring's data area, only to consumer_pos.
 *   - It can be absent, killed mid-batch, or stalled indefinitely. The worst
 *     outcome is that rings fill and TMM counts drops --- a counted gap, which
 *     is the designed behaviour, not a failure.
 *
 * WHY NO BROKER CLIENT IS LINKED IN. Writing JSON lines to stdout and piping to a
 * publisher (or a file) keeps the *agent* free of a
 * broker dependency too. If the downstream pipe breaks, this process dies on
 * EPIPE, and TMM still does not care. Linking a reconnecting client here would
 * put retry logic one process closer to the data plane for no benefit, since the
 * decoupling that matters already happened at the shared-memory boundary.
 *
 *   ls_drain --segment /dev/shm/ls_tp_ring | <publisher>
 *
 * ON WHICH BROKER: BNK already runs RabbitMQ --- the f5-rabbit pod, reachable at
 * amqps://rabbitmq-server.default:5671. NATS appeared in earlier examples here and
 * is NOT deployed anywhere in the cluster, which made the comment read as a
 * recommendation for something absent. The choice stays outside this file either
 * way; that is the whole point of writing to stdout.
 *   ls_drain --segment /dev/shm/ls_tp_ring > records.jsonl
 *
 * DELIVERY IS AT-LEAST-ONCE. Records are written BEFORE consumer_pos advances,
 * so a crash mid-batch re-delivers rather than loses. Consumers dedupe on
 * (slot, seq); seq is atomic in the producer precisely so that pair is unique.
 * `slot` was called `tmm` until 2026-08-18 and always carried the slot number ---
 * the producer passes (unsigned)slot and always did. The key was a false claim.
 * The other order --- acknowledge then publish --- loses records silently on a
 * crash, which is the worse failure for an analytics feed.
 *
 * A HOSTILE OR BUGGY CONSUMER, stated plainly because it is a real boundary:
 * this process maps the segment read-write, because advancing consumer_pos
 * requires it. A consumer that writes a nonsense consumer_pos can therefore make
 * the producer's `prod - cons` underflow, which makes the full-check true
 * forever and turns the ring into a permanent drop-and-count. It cannot crash
 * TMM, corrupt TMM's memory, or block the data plane --- but it can silence its
 * own feed. Whoever can write this segment can already stop the telemetry by
 * not running; the segment is 0600 and this is a TMA item, not a hole.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Escaping lives in its own header so check_json.c can test it. */
#include "../ls_json.h"

#include "../ls_tp_ring.h"

static volatile sig_atomic_t g_stop;
static void on_signal(int s) { (void)s; g_stop = 1; }

static const char *VERSION_NAME[4] = { "UNKNOWN", "HTTP/0.9", "HTTP/1.1", "HTTP/1.0" };

/* The 40-byte tmm:l7:http_headers record. Kept in the same order as
 * substrate/ls_tp_http.h; schema_id in each record is what authorises this
 * decode, and an unknown schema is emitted as raw rather than guessed at. */
struct http_rec {
    uint32_t parse_err;          /* the PARSER's verdict --- classify with this */
    uint32_t err;                /* the filter's final disposition, NOT the parse */
    uint32_t reject_reason, passthru, version, method;
    uint32_t header_count, status_code, invalid_flags, body_pos, hdr_bytes;
};

/* ERR_MORE_DATA is 17 --- headers spanning two packets. Not a fault, and the
 * reason `parse_err != 0` is the wrong test. */
#define ERR_VAL 3u
#define ERR_BOUNDS 5u
#define ERR_REJECT 16u
#define MALFORMED(r) ((r)->parse_err == ERR_VAL || (r)->parse_err == ERR_BOUNDS || \
                      (r)->parse_err == ERR_REJECT)

/* The three classes come apart, so name them rather than collapsing them. */
static const char *
klass(const struct http_rec *r)
{
    if (!MALFORMED(r))       return "normal";
    return r->passthru ? "waived" : "refused";
}

/* struct ls_ctx_rst --- substrate/ls_ctx_rst.h. The teardown record: which line
 * of TMM's own source decided to close this connection. */
struct rst_rec {
    uint32_t cookie_lo, cookie_hi;   /* TMM's flow cookie, split (align 4)   */
    uint32_t lineno, err, reason, file_len, cause_len;
    char     file[28];
    char     cause[36];              /* rst_why's 6th argument (Phase 3)     */
};

/* Which of the four RST_WHY* functions produced this record. `hook` stays "reset"
 * for all of them so a consumer keying on it does not break; this is the additive
 * detail. Knowing the function matters because they differ in ARGUMENT SHAPE --- the
 * preserve pair has no `reason` --- and because a site's macro is otherwise only
 * discoverable by reading TMM's source. */
static const char *
rst_fn_name(uint32_t id)
{
    switch (id) {
    case LS_TP_HOOK_RST:        return "rst_why";
    case LS_TP_HOOK_RST_VA:     return "rst_why_va";
    case LS_TP_HOOK_RST_PRE:    return "rst_why_preserve";
    case LS_TP_HOOK_RST_PRE_VA: return "rst_why_preserve_va";
    default:                    return "?";
    }
}

static void
emit_rst(const struct ls_rec *h, const struct rst_rec *r)
{
    uint32_t fn = r->file_len  < sizeof r->file  ? r->file_len  : (uint32_t)sizeof r->file;
    uint32_t cn = r->cause_len < sizeof r->cause ? r->cause_len : (uint32_t)sizeof r->cause;

    printf("{\"ts_ns\":%llu,\"seq\":%llu,\"slot\":%u,\"hook\":\"reset\","
           "\"fn\":\"%s\",\"schema\":%u,\"file\":\"",
           (unsigned long long)h->ts_ns, (unsigned long long)h->seq, h->slot,
           rst_fn_name(h->hook_id), h->schema_id);
    ls_json_str(r->file, fn);
    printf("\",\"line\":%u,\"err\":%u,\"reason\":%u,",
           r->lineno, r->err, r->reason);
    /* The cookie as ONE hex string, reassembled from the two halves. Hex rather than
     * decimal because it is an opaque identifier to be compared, never arithmetic on,
     * and "flow":"0" reads clearly as "no flow" --- which is a legitimate case, not a
     * missing field. */
    printf("\"flow\":\"%08x%08x\",\"cause\":\"",
           r->cookie_hi, r->cookie_lo);
    ls_json_str(r->cause, cn);
    printf("\"}\n");
}

/* SIZES PINNED HERE TOO. Each of these layouts is defined in THREE places --- the host
 * builder's header, the program's mirror, and this file --- because the drain is a
 * separate process sharing only bytes. Nothing compared the third against the other two.
 * A drain struct one byte off decodes every field past the divergence from the wrong
 * offset and prints plausible values, which is worse than refusing.
 *
 * These asserts are cheap and they are the only thing standing between a header edit and
 * a consumer that silently misreads the feed. */
_Static_assert(sizeof(struct rst_rec) == 92, "rst_rec must match struct ls_ctx_rst (92)");
_Static_assert(sizeof(struct http_rec) == 44, "http_rec must match the 44-byte HTTP record");

/* struct ls_ctx_sslerr --- substrate/ls_ctx_sslerr.h. WHY the TLS handshake or record
 * layer failed, from the site inside TMM that decided it. 96 bytes: AT PREVAIL's ctx
 * ceiling rather than under it, so this layout cannot grow. */
struct sslerr_rec {
    uint32_t cookie_lo, cookie_hi;   /* same cookie the reset record carries */
    uint32_t lineno, alert, func_len, msg_len;
    char     func[32];               /* __func__ --- ssl_err passes no __FILE__ */
    char     msg[40];                /* the first vararg                        */
};

/* The TLS AlertDescription, named. Rendering it matters more than it looks: the alert is
 * the ONE part of this a client can also see, so naming it is what lets someone line up
 * "my browser said handshake_failure" with the site inside TMM that sent it. Numbers are
 * the wire values from RFC 8446 §6.2 and its predecessors. */
_Static_assert(sizeof(struct sslerr_rec) == 96,
               "sslerr_rec must match struct ls_ctx_sslerr (96, AT PREVAIL's ceiling)");

static const char *
ssl_alert_name(uint32_t a)
{
    switch (a) {
    case 0:   return "close_notify";
    case 10:  return "unexpected_message";
    case 20:  return "bad_record_mac";
    case 22:  return "record_overflow";
    case 40:  return "handshake_failure";
    case 42:  return "bad_certificate";
    case 43:  return "unsupported_certificate";
    case 46:  return "certificate_unknown";
    case 47:  return "illegal_parameter";
    case 48:  return "unknown_ca";
    case 50:  return "decode_error";
    case 51:  return "decrypt_error";
    case 70:  return "protocol_version";
    case 80:  return "internal_error";
    case 112: return "unrecognized_name";
    /* Not a fallback to a plausible name: an alert we do not know is reported as its
     * number, so a reader sees an unfamiliar value rather than a wrong label. */
    default:  return "";
    }
}

static void
emit_sslerr(const struct ls_rec *h, const struct sslerr_rec *r)
{
    uint32_t fn = r->func_len < sizeof r->func ? r->func_len : (uint32_t)sizeof r->func;
    uint32_t mn = r->msg_len  < sizeof r->msg  ? r->msg_len  : (uint32_t)sizeof r->msg;
    const char *an = ssl_alert_name(r->alert);

    /* `fn` here is __func__, so it names the FUNCTION rather than the file --- the
     * opposite way round from the reset record, which has __FILE__ and no function. Both
     * fields are emitted under the names that say which is which: "func" not "file". */
    printf("{\"ts_ns\":%llu,\"seq\":%llu,\"slot\":%u,\"hook\":\"sslerr\","
           "\"schema\":%u,\"func\":\"",
           (unsigned long long)h->ts_ns, (unsigned long long)h->seq, h->slot,
           h->schema_id);
    ls_json_str(r->func, fn);
    printf("\",\"line\":%u,\"alert\":%u,\"alert_name\":\"%s\",",
           r->lineno, r->alert, an);
    /* TRUNCATION REPORTED, not hidden. func_len or msg_len at MAX-1 means the string was
     * cut --- 4.4% of function names and 11.2% of messages across the 475 sites. A
     * consumer diffing records needs to know it is comparing a prefix. */
    printf("\"truncated\":%s,",
           (fn == sizeof r->func - 1 || mn == sizeof r->msg - 1) ? "true" : "false");
    /* The SAME cookie the reset record carries for this connection, so the two feeds
     * join on it: "TLS failed here, then the connection was reset there". */
    printf("\"flow\":\"%08x%08x\",\"msg\":\"", r->cookie_hi, r->cookie_lo);
    ls_json_str(r->msg, mn);
    printf("\"}\n");
}

static const char *
hook_name(uint32_t id)
{
    switch (id) {
    case LS_TP_HOOK_HTTP1_HDRS: return "http1";
    case LS_TP_HOOK_HTTP2_HDRS: return "http2";
    case LS_TP_HOOK_HTTP3_HDRS: return "http3";
    case LS_TP_HOOK_RST:
    case LS_TP_HOOK_RST_VA:
    case LS_TP_HOOK_RST_PRE:
    case LS_TP_HOOK_RST_PRE_VA: return "reset";
    case LS_TP_HOOK_SSLERR:     return "sslerr";
    default:                    return "?";
    }
}

static void
emit_http(const struct ls_rec *h, const struct http_rec *r)
{
    printf("{\"ts_ns\":%llu,\"seq\":%llu,\"slot\":%u,\"hook\":\"%s\",\"schema\":%u,"
           "\"class\":\"%s\",\"parse_err\":%u,\"err\":%u,"
           "\"reject_reason\":%u,\"passthru\":%u,"
           "\"version\":\"%s\",\"method\":%u,\"header_count\":%u,"
           "\"status_code\":%u,\"invalid_flags\":%u,\"body_pos\":%u,"
           "\"hdr_bytes\":%u}\n",
           (unsigned long long)h->ts_ns, (unsigned long long)h->seq, h->slot,
           hook_name(h->hook_id), h->schema_id,
           klass(r), r->parse_err, r->err, r->reject_reason, r->passthru,
           VERSION_NAME[r->version & 3], r->method, r->header_count,
           r->status_code, r->invalid_flags, r->body_pos, r->hdr_bytes);
}

static void
emit_raw(const struct ls_rec *h, const unsigned char *p, int n)
{
    int i;
    printf("{\"ts_ns\":%llu,\"seq\":%llu,\"slot\":%u,\"hook\":\"%s\",\"schema\":%u,\"raw\":\"",
           (unsigned long long)h->ts_ns, (unsigned long long)h->seq, h->slot,
           hook_name(h->hook_id), h->schema_id);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\"}\n");
}

int
main(int argc, char **argv)
{
    const char *path = NULL;
    long idle_us = 2000, max_idle_us = 200000;
    int once = 0, quiet_stats = 0;
    struct ls_tp_seg *seg;
    unsigned long long delivered = 0, last_drops = 0;
    long backoff;

    static struct option opts[] = {
        { "segment",  required_argument, 0, 's' },
        { "interval", required_argument, 0, 'i' },
        { "once",     no_argument,       0, '1' },
        { "no-stats", no_argument,       0, 'q' },
        { "help",     no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    int c;
    while ((c = getopt_long(argc, argv, "s:i:1qh", opts, NULL)) != -1) {
        switch (c) {
        case 's': path = optarg; break;
        case 'i': idle_us = atol(optarg); break;
        case '1': once = 1; break;
        case 'q': quiet_stats = 1; break;
        default:
            fprintf(stderr,
                "usage: %s --segment PATH [--interval US] [--once] [--no-stats]\n"
                "\n"
                "Consumes tracepoint records from the shared segment and writes\n"
                "JSON lines to stdout. Pipe them anywhere:\n"
                "\n"
                "  %s -s /dev/shm/ls_tp_ring | <publisher>   (BNK runs RabbitMQ, not NATS)\n"
                "  %s -s /dev/shm/ls_tp_ring > records.jsonl\n"
                "\n"
                "TMM does not depend on this process. Killing it, stalling it, or\n"
                "never starting it costs counted drops and nothing else.\n",
                argv[0], argv[0], argv[0]);
            return 2;
        }
    }
    if (path == NULL) {
        fprintf(stderr, "*** --segment is required\n");
        return 2;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_DFL);      /* downstream closed: die, do not spin */

    seg = ls_tp_seg_open(path, 0);
    if (seg == NULL) {
        fprintf(stderr,
            "*** cannot open %s as a tracepoint segment.\n"
            "    If the file is all zeros, this process mapped its OWN tmpfs\n"
            "    rather than a segment shared with TMM --- in Kubernetes that\n"
            "    means /dev/shm is not an emptyDir with medium: Memory in BOTH\n"
            "    containers. It looks exactly like 'no traffic'.\n", path);
        return 1;
    }
    fprintf(stderr, "ls_drain: %s mapped, %u rings x %u bytes\n",
            path, seg->n_rings, seg->ring_data_size);

    backoff = idle_us;
    while (!g_stop) {
        int found = 0;
        unsigned int i;
        unsigned long long drops = 0;

        for (i = 0; i < seg->n_rings; i++) {
            struct ls_ring *r = ls_tp_seg_ring(seg, i);
            struct ls_rec h;
            unsigned char buf[512];
            int n;

            drops += atomic_load_explicit(&r->drops, memory_order_relaxed);

            /* Drain this ring until empty. ls_ring_consume acknowledges by
             * advancing consumer_pos --- which is what separates a drain from a
             * reader. A STREAM ring that is read but never acknowledged fills,
             * and TMM starts counting drops that nothing caused. */
            while ((n = ls_ring_consume(r, &h, buf, sizeof buf)) >= 0) {
                /* DISPATCH ON SCHEMA, NOT HOOK ID. This read `h.hook_id ==
                 * LS_TP_HOOK_RST`, which is id 4 --- plain rst_why alone. The reset
                 * family has four ids (4,5,6,7) all sharing schema 3, so records from
                 * rst_why_va, rst_why_preserve and rst_why_preserve_va never matched and
                 * fell through to emit_raw as hex.
                 *
                 * That is the SECOND HALF of the 2026-08-17 bug, left undone. The
                 * producer was fixed then --- ls_tp_schema_for() stopped labelling three
                 * of the four as HTTP --- but the consumer kept keying on one id. So the
                 * pair still disagreed, just in the other direction, and it went unseen
                 * because only rst_why was armed in the runs afterwards.
                 *
                 * The separation is the fix: SCHEMA decides the LAYOUT (it is the version
                 * of the byte format), hook_id decides only the LABEL, which is what
                 * rst_fn_name already does. */
                if (h.schema_id == LS_TP_SCHEMA_RST && n == (int)sizeof(struct rst_rec))
                    emit_rst(&h, (const struct rst_rec *)buf);
                else if (h.schema_id == LS_TP_SCHEMA_HTTP && n == (int)sizeof(struct http_rec))
                    emit_http(&h, (const struct http_rec *)buf);
                /* The LENGTH is checked as well as the schema, for every shape. A schema
                 * saying "sslerr" over a payload of the wrong size is a producer bug, and
                 * decoding it anyway would print plausible fields read from the wrong
                 * offsets. Falling through to emit_raw makes it visible instead. */
                else if (h.schema_id == LS_TP_SCHEMA_SSLERR && n == (int)sizeof(struct sslerr_rec))
                    emit_sslerr(&h, (const struct sslerr_rec *)buf);
                else
                    emit_raw(&h, buf, n);
                delivered++;
                found = 1;
                if (g_stop)
                    break;
            }
        }

        /* Records reach stdout BEFORE the next poll observes the acknowledgement,
         * and fflush here is what makes at-least-once real rather than nominal:
         * an unflushed buffer lost on a crash is a record acknowledged and never
         * delivered, which is the failure this ordering exists to prevent. */
        fflush(stdout);

        if (!quiet_stats && drops != last_drops) {
            fprintf(stderr, "ls_drain: drops now %llu (+%llu) --- ring filled; "
                            "TMM never waited\n",
                    drops, drops - last_drops);
            last_drops = drops;
        }

        if (once)
            break;

        /* Adaptive backoff: spin close while records flow, ease off when idle.
         * There is no eventfd in the ring, so this polls. */
        if (found) {
            backoff = idle_us;
        } else {
            struct timespec ts = { backoff / 1000000, (backoff % 1000000) * 1000 };
            nanosleep(&ts, NULL);
            backoff = backoff * 2 > max_idle_us ? max_idle_us : backoff * 2;
        }
    }

    fflush(stdout);
    fprintf(stderr, "ls_drain: exit, %llu record(s) delivered, %llu drop(s) seen\n",
            delivered, last_drops);
    return 0;
}
