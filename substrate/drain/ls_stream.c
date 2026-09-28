/* Separate-process STREAM reader: no cursor advance before downstream ACK.
 * The peer must durably journal a frame before acknowledging it. No TMM code
 * uses this executable. Legacy ls_drain must not share its segment.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/sysmacros.h>
#include <time.h>
#include "../ls_tp_ring.h"

static const char *segment_path;
static pid_t producer;
static uint64_t expected_start;
static struct stat segment_stat, exe_stat;
static volatile sig_atomic_t stopped;
static void stop(int sig) { (void)sig; stopped = 1; }
static void fail(const char *message) { fprintf(stderr, "ls_stream: %s\n", message); exit(1); }

static uint64_t start_time(pid_t pid)
{
    char path[64], buf[4096], *save, *p;
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    p = fgets(buf, sizeof buf, f);
    fclose(f);
    if (!p || !(p = strrchr(buf, ')'))) return 0;
    p = strtok_r(p + 1, " ", &save);
    for (int field = 3; p && field < 22; field++) p = strtok_r(NULL, " ", &save);
    return p ? strtoull(p, NULL, 10) : 0;
}

static void same_source(void)
{
    struct stat s, e;
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/exe", (long)producer);
    if (start_time(producer) != expected_start || stat(path, &e) ||
            e.st_dev != exe_stat.st_dev || e.st_ino != exe_stat.st_ino ||
            stat(segment_path, &s) || s.st_dev != segment_stat.st_dev ||
            s.st_ino != segment_stat.st_ino || s.st_size != segment_stat.st_size)
        fail("source identity changed; no acknowledgement");
}

/* A live PID alone is not evidence that it owns the supplied segment. Require
 * a shared writable mapping of this inode in the pinned producer process. */
static void mapped_source(void)
{
    char path[64], line[4096], perms[5];
    unsigned long low, high;
    unsigned major_id, minor_id;
    unsigned long long offset, inode;
    int found = 0;
    snprintf(path, sizeof path, "/proc/%ld/maps", (long)producer);
    FILE *f = fopen(path, "r");
    if (!f) fail("producer mappings unavailable");
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%lx-%lx %4s %llx %x:%x %llu", &low, &high,
                   perms, &offset, &major_id, &minor_id, &inode) == 7 &&
                !strcmp(perms, "rw-s") && !offset &&
                high - low >= LS_TP_SEG_SZ && inode == segment_stat.st_ino &&
                major_id == major(segment_stat.st_dev) &&
                minor_id == minor(segment_stat.st_dev)) found = 1;
    }
    fclose(f);
    if (!found) fail("producer does not map this segment");
}

static void acknowledge(const char *token)
{
    char line[128], expected[128];
    if (fflush(stdout) || ferror(stdout)) fail("output failed before ACK");
    snprintf(expected, sizeof expected, "ACK %s\n", token);
    if (!fgets(line, sizeof line, stdin) || strcmp(line, expected))
        fail("missing or invalid ACK; cursor retained");
    same_source();
    mapped_source();
}

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 5 || (argc == 5 && strcmp(argv[4], "--once"))) {
        fprintf(stderr, "usage: ls_stream SEGMENT PRODUCER_PID START_TICKS [--once]\n");
        return 2;
    }
    pid_t parent = getppid();
    if (parent == 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
        fail("collector parent unavailable");
    segment_path = argv[1];
    producer = (pid_t)strtol(argv[2], NULL, 10);
    expected_start = strtoull(argv[3], NULL, 10);
    if (producer <= 0 || !expected_start || start_time(producer) != expected_start)
        fail("producer identity mismatch");
    char path[64], boot[64];
    struct stat ns;
    snprintf(path, sizeof path, "/proc/%ld/exe", (long)producer);
    if (stat(path, &exe_stat) || stat("/proc/self/ns/pid", &ns)) fail("source stat failed");
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!f || fscanf(f, "%63s", boot) != 1) fail("boot identity unavailable");
    fclose(f);
    if (strspn(boot, "0123456789abcdef-") != strlen(boot)) fail("invalid boot identity");
    int fd = open(segment_path, O_RDWR | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &segment_stat) || !S_ISREG(segment_stat.st_mode) ||
            segment_stat.st_size != (off_t)LS_TP_SEG_SZ) fail("invalid segment file");
    if (flock(fd, LOCK_EX | LOCK_NB)) fail("another cooperative reader owns this segment");
    struct ls_tp_seg *s = mmap(NULL, LS_TP_SEG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (s == MAP_FAILED) fail("cannot map segment");
    if (s->magic != LS_TP_SEG_MAGIC || s->version != LS_TP_SEG_VERSION ||
            s->n_rings != LS_TP_MAX_RINGS || s->ring_stride != LS_TP_STRIDE ||
            s->ring_data_size != LS_TP_RING_BYTES) fail("invalid segment geometry");
    struct sigaction action = {0};
    action.sa_handler = stop;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL))
        fail("cannot install stop handler");
    same_source();
    mapped_source();
    printf("{\"kind\":\"source\",\"token\":\"H\",\"boot\":\"%s\","
           "\"pid_namespace\":\"%ju\",\"pid\":\"%ld\",\"start\":\"%" PRIu64 "\","
           "\"segment_device\":\"%ju\",\"segment_inode\":\"%ju\","
           "\"exe_device\":\"%ju\",\"exe_inode\":\"%ju\",\"segment_version\":%u}\n",
           boot, (uintmax_t)ns.st_ino, (long)producer, expected_start,
           (uintmax_t)segment_stat.st_dev, (uintmax_t)segment_stat.st_ino,
           (uintmax_t)exe_stat.st_dev, (uintmax_t)exe_stat.st_ino, s->version);
    acknowledge("H");
    uint64_t last_drops[LS_TP_MAX_RINGS];
    for (unsigned i = 0; i < LS_TP_MAX_RINGS; i++) last_drops[i] = UINT64_MAX;
    do {
        int found = 0;
        same_source();
        unsigned claimed = atomic_load_explicit(&s->claimed, memory_order_acquire);
        if (claimed > s->n_rings) fail("ring claims exceed capacity");
        for (unsigned i = 0; i < claimed && !stopped; i++) {
            /* Use verified compile-time geometry even if the header changes. */
            struct ls_ring *r = (void *)((uint8_t *)s + sizeof *s + i * LS_TP_STRIDE);
            if (r->magic != LS_RING_MAGIC || r->version != 1 ||
                    r->policy != LS_RING_STREAM || r->data_size != LS_TP_RING_BYTES)
                fail("invalid ring geometry/policy");
            uint64_t drops = atomic_load_explicit(&r->drops, memory_order_relaxed);
            char token[96];
            if (drops != last_drops[i]) {
                snprintf(token, sizeof token, "D:%u:%" PRIu64, i, drops);
                printf("{\"kind\":\"ring_health\",\"token\":\"%s\",\"ring\":%u,"
                       "\"drops\":\"%" PRIu64 "\",\"drop_bytes\":\"%" PRIu64 "\"}\n",
                       token, i, drops, atomic_load_explicit(&r->drop_bytes, memory_order_relaxed));
                acknowledge(token);
                last_drops[i] = drops;
            }
            uint64_t cons = atomic_load_explicit(&r->consumer_pos, memory_order_acquire);
            uint64_t prod = atomic_load_explicit(&r->producer_pos, memory_order_acquire);
            if (cons > prod || prod - cons > r->data_size ||
                    (cons | prod) & (LS_RING_ALIGN - 1)) fail("invalid ring positions");
            if (cons == prod) continue;
            uint32_t off = cons & (r->data_size - 1);
            uint8_t *data = ls_ring_data(r) + off;
            uint32_t hdr = atomic_load_explicit((_Atomic uint32_t *)(void *)data, memory_order_acquire);
            if (hdr & LS_RING_BUSY) continue;
            uint32_t body = hdr & LS_RING_LEN_MASK;
            if (body > r->data_size - LS_RING_HDR_SZ) fail("invalid record length");
            uint32_t step = ls_ring_round(LS_RING_HDR_SZ + body);
            if (step > r->data_size - off || step > prod - cons) fail("record outside committed range");
            snprintf(token, sizeof token, "R:%u:%" PRIu64 ":%" PRIu64, i, cons, cons + step);
            printf("{\"kind\":\"%s\",\"token\":\"%s\",\"ring\":%u,"
                   "\"begin\":\"%" PRIu64 "\",\"end\":\"%" PRIu64 "\"",
                   hdr & LS_RING_DISCARD ? "discard" : "record", token, i, cons, cons + step);
            if (!(hdr & LS_RING_DISCARD)) {
                struct ls_rec rec;
                unsigned char payload[512];
                if (body < sizeof rec || body - sizeof rec > sizeof payload) fail("unsupported record size");
                memcpy(&rec, data + LS_RING_HDR_SZ, sizeof rec);
                if (rec.len != body - sizeof rec) fail("record/payload length mismatch");
                memcpy(payload, data + LS_RING_HDR_SZ + sizeof rec, rec.len);
                printf(",\"hook_id\":%u,\"schema\":%u,\"slot\":%u,\"seq\":\"%" PRIu64
                       "\",\"ts_ns\":\"%" PRIu64 "\",\"data\":\"",
                       rec.hook_id, rec.schema_id, rec.slot, rec.seq, rec.ts_ns);
                for (unsigned j = 0; j < rec.len; j++) printf("%02x", payload[j]);
                printf("\"");
            }
            printf("}\n");
            acknowledge(token);
            if (atomic_load_explicit(&r->consumer_pos, memory_order_acquire) != cons)
                fail("another consumer moved the cursor");
            atomic_store_explicit(&r->consumer_pos, cons + step, memory_order_release);
            found = 1;
        }
        if (argc == 5 && !found) break;
        if (!found) { struct timespec delay = {0, 2000000}; nanosleep(&delay, NULL); }
    } while (!stopped);
    munmap(s, LS_TP_SEG_SZ);
    close(fd);
    return 0;
}
