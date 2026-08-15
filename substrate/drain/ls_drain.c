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
 * WHY NO BROKER CLIENT IS LINKED IN. Writing JSON lines to stdout and piping to
 * `nats pub` (or a ZeroMQ publisher, or a file) keeps the *agent* free of a
 * broker dependency too. If the downstream pipe breaks, this process dies on
 * EPIPE, and TMM still does not care. Linking a reconnecting client here would
 * put retry logic one process closer to the data plane for no benefit, since the
 * decoupling that matters already happened at the shared-memory boundary.
 *
 *   ls_drain --segment /dev/shm/ls_tp_ring | nats pub --stdin tmm.l7.http
 *   ls_drain --segment /dev/shm/ls_tp_ring > records.jsonl
 *
 * DELIVERY IS AT-LEAST-ONCE. Records are written BEFORE consumer_pos advances,
 * so a crash mid-batch re-delivers rather than loses. Consumers dedupe on
 * (tmm_id, seq); seq is atomic in the producer precisely so that pair is unique.
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

#include "../ls_tp_ring.h"

static volatile sig_atomic_t g_stop;
static void on_signal(int s) { (void)s; g_stop = 1; }

static const char *VERSION_NAME[4] = { "UNKNOWN", "HTTP/0.9", "HTTP/1.1", "HTTP/1.0" };

/* The 40-byte tmm:l7:http_headers record. Kept in the same order as
 * substrate/ls_tp_http.h; schema_id in each record is what authorises this
 * decode, and an unknown schema is emitted as raw rather than guessed at. */
struct http_rec {
    uint32_t err, reject_reason, passthru, version, method;
    uint32_t header_count, status_code, invalid_flags, body_pos, hdr_bytes;
};

static void
emit_http(const struct ls_rec *h, const struct http_rec *r)
{
    printf("{\"seq\":%llu,\"tmm\":%u,\"hook\":%u,\"schema\":%u,"
           "\"err\":%u,\"reject_reason\":%u,\"passthru\":%u,"
           "\"version\":\"%s\",\"method\":%u,\"header_count\":%u,"
           "\"status_code\":%u,\"invalid_flags\":%u,\"body_pos\":%u,"
           "\"hdr_bytes\":%u}\n",
           (unsigned long long)h->seq, h->tmm_id, h->hook_id, h->schema_id,
           r->err, r->reject_reason, r->passthru,
           VERSION_NAME[r->version & 3], r->method, r->header_count,
           r->status_code, r->invalid_flags, r->body_pos, r->hdr_bytes);
}

static void
emit_raw(const struct ls_rec *h, const unsigned char *p, int n)
{
    int i;
    printf("{\"seq\":%llu,\"tmm\":%u,\"hook\":%u,\"schema\":%u,\"raw\":\"",
           (unsigned long long)h->seq, h->tmm_id, h->hook_id, h->schema_id);
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
                "  %s -s /dev/shm/ls_tp_ring | nats pub --stdin tmm.l7.http\n"
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
                if (h.schema_id == LS_TP_SCHEMA_HTTP && n == (int)sizeof(struct http_rec))
                    emit_http(&h, (const struct http_rec *)buf);
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
