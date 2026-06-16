/*
 * minimm — a "mini-TMM": a transparent TCP bent-pipe relay with an inline
 * inspection/enforcement stage, built to exercise the Live Shield mechanism
 * without needing real TMM internals.
 *
 * Structural properties it shares with TMM (the ones that matter for the design):
 *   - a single-threaded epoll *poll loop* moving bytes client<->upstream,
 *   - an inline eval stage on the client->upstream path,
 *   - a designed-in, named "filter" hook point at the decision site,
 *   - a deliberately vulnerable parser reached only on LS_PASS (the synthetic CVE).
 *
 * Modes (subcommands):
 *   minimm relay  --listen PORT --upstream HOST:PORT   the bent pipe + shield
 *   minimm echo   --listen PORT                        a trivial frame sink (test upstream)
 *   minimm ctl    mode {disable|monitor|enforce}       set shield mode (shared map)
 *   minimm ctl    stats                                read evidence counters
 *   minimm ctl    flightrec                            dump the observe-mode ring (§3.1)
 *
 * Wire framing (toy, just enough to carry an opcode): big-endian
 *   [2B opcode][2B payload_len][payload ...]
 *
 * Synthetic CVE ("CVE-2026-22548" analog): process_frame() dispatches on opcode
 * through a fixed handler table WITHOUT a bounds check. A frame whose opcode is
 * outside the table indexes out of bounds and calls a wild pointer -> the relay
 * process dies (the data plane goes down). The SIRT predicate is therefore
 * "opcode >= N_HANDLERS"; the shield drops/resets such frames before dispatch.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ls_shield.h"

/* ----------------------------------------------------------------------- */
/* Shared "map" (POSIX shm) — mode + evidence counters (design §6, §7).     */
/* ----------------------------------------------------------------------- */

static struct ls_shared *g_ls;   /* mapped shared region, never NULL after init */

static struct ls_shared *ls_map_open(int create)
{
    int flags = create ? (O_RDWR | O_CREAT) : O_RDWR;
    int fd = shm_open(LS_SHM_NAME, flags, 0600);
    if (fd < 0) return NULL;
    if (create && ftruncate(fd, sizeof(struct ls_shared)) != 0) { close(fd); return NULL; }
    void *p = mmap(NULL, sizeof(struct ls_shared), PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return NULL;
    struct ls_shared *s = p;
    if (create && s->abi_version == 0) {
        s->abi_version = LS_ABI_VERSION;
        s->mode = LS_MONITOR;   /* default for this build; crash-class would be ENFORCE (§7.1) */
        s->hits = 0;
        s->enforced = 0;
        s->last_opcode = 0;
    }
    return s;
}

/* ----------------------------------------------------------------------- */
/* The vulnerable data-plane parser (the synthetic CVE lives here).         */
/* ----------------------------------------------------------------------- */

#define N_HANDLERS 4
struct frame { uint16_t opcode; uint16_t len; const uint8_t *payload; };

static void h_noop(struct frame *f)   { (void)f; }
static void h_upper(struct frame *f)  { (void)f; }
static void h_count(struct frame *f)  { (void)f; }
static void h_echo(struct frame *f)   { (void)f; }
typedef void (*handler_fn)(struct frame *);
static handler_fn g_handlers[N_HANDLERS] = { h_noop, h_upper, h_count, h_echo };

/* PLANTED BUG: no bounds check on f->opcode before indexing the table.
 * Compiled in its own translation-unit-ish path; reached only on LS_PASS. */
__attribute__((noinline))
static void process_frame(struct frame *f)
{
    handler_fn h = g_handlers[f->opcode];   /* OOB read when opcode >= N_HANDLERS */
    h(f);                                    /* wild call -> process death         */
}

/* ----------------------------------------------------------------------- */
/* The designed-in "filter" hook point (design §5.3, §6.1).                 */
/* ----------------------------------------------------------------------- */

/* SIRT-derived predicate: narrow, "this should never legitimately occur". */
static int matches_crash_precondition(const struct ls_ctx *ctx)
{
    return ctx->opcode >= N_HANDLERS;
}

#if defined(LS_UBPF) || defined(LS_TRACE)
/*
 * The embedded userspace VM (uBPF) — the real product model: the program is
 * eBPF BYTECODE executed in-process by a VM the host links in, called at a
 * designed-in hook point (design §3.1; no kernel, no injection). Two attach
 * modes share this exact machinery (design §6.1):
 *
 *   LS_UBPF  -> filter   : host acts on the return value (PASS/DROP/RESET).
 *                          Shield return: 0=PASS, 1=match/monitor, 2=match/enforce.
 *   LS_TRACE -> observe  : host runs the program for TELEMETRY only and never
 *                          changes flow — a TMM tracepoint. The program returns
 *                          a sampled value (e.g. the opcode) the host histograms.
 *
 * Same VM, same hook-point, same load + §9 verify gate; only what the host does
 * with the result differs. This is why one embedded-eBPF substrate gives F5
 * both Live Shield (enforce) AND eBPF observability ("eob") inside TMM.
 */
#include "ubpf.h"
#include <sys/wait.h>
static struct ubpf_vm *g_vm;

/*
 * The §9 verify-before-load gate. If LS_VERIFIER is set (e.g. to PREVAIL's
 * prevail-cli), the shield bytecode is statically verified BEFORE it is loaded
 * into the VM. Nonzero exit => reject => the shield is NOT loaded (fail closed).
 * If LS_VERIFIER is unset, the gate is skipped (the verifier is the product's,
 * not the prototype's, but the hook is real). Optional LS_VERIFY_SECTION names
 * the program section/type for the verifier.
 */
static int ls_verify(const char *obj_path)
{
    const char *verifier = getenv("LS_VERIFIER");
    if (!verifier || !*verifier) return 0;   /* no verifier configured -> skip */
    const char *section = getenv("LS_VERIFY_SECTION");
    fprintf(stderr, "[minimm] verifying shield with %s ...\n", verifier);
    pid_t pid = fork();
    if (pid == 0) {
        if (section)
            execlp(verifier, verifier, "-q", "--section", section, obj_path, (char *)NULL);
        else
            execlp(verifier, verifier, "-q", obj_path, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) < 0) return -1;
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

static int ls_ubpf_init(const char *obj_path)
{
    /* §9: verify first; refuse to load unverifiable bytecode. */
    if (ls_verify(obj_path) != 0) {
        fprintf(stderr, "[minimm] shield REJECTED by verifier (fail closed): %s\n", obj_path);
        return -1;
    }
    FILE *f = fopen(obj_path, "rb");
    if (!f) { perror(obj_path); return -1; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    void *buf = malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return -1; }
    fclose(f);
    g_vm = ubpf_create();
    char *err = NULL;
    int rc = ubpf_load_elf(g_vm, buf, (size_t)n, &err);
    free(buf);
    if (rc < 0) {
        fprintf(stderr, "[minimm] uBPF shield load failed: %s\n", err ? err : "?");
        return -1;
    }
    fprintf(stderr, "[minimm] uBPF shield loaded%s from %s\n",
            getenv("LS_VERIFIER") ? " (verified)" : "", obj_path);
    return 0;
}

#if defined(LS_TRACE)
/*
 * Flight recorder (substrate §3.1): push a frame summary into the shm ring.
 * The host owns the ring (uBPF has no native maps); the observe program only
 * supplies the sample + the trigger flag. One ring here; per-CPU in production.
 */
static void ls_fr_push(const struct ls_ctx *ctx)
{
    uint32_t i = g_ls->fr_head;
    struct ls_fr_entry *e = &g_ls->fr_ring[i];
    e->opcode = ctx->opcode;
    e->payload_len = ctx->payload_len;
    e->avail_len = ctx->avail_len;
    for (uint32_t k = 0; k < sizeof(e->head); k++)
        e->head[k] = (k < ctx->avail_len && k < sizeof(ctx->head)) ? ctx->head[k] : 0;
    g_ls->fr_head = (i + 1) % LS_FR_DEPTH;
    g_ls->fr_seen++;
}

/* Freeze + dump the ring oldest->newest (the run-up into the trigger). */
static void ls_fr_dump(const char *why)
{
    uint64_t seen = g_ls->fr_seen;
    uint32_t depth = seen < LS_FR_DEPTH ? (uint32_t)seen : LS_FR_DEPTH;
    uint32_t start = (g_ls->fr_head + LS_FR_DEPTH - depth) % LS_FR_DEPTH;
    fprintf(stderr, "[minimm] *** FLIGHT RECORDER DUMP (%s): last %u frame(s) into the trigger ***\n",
            why, depth);
    for (uint32_t n = 0; n < depth; n++) {
        struct ls_fr_entry *e = &g_ls->fr_ring[(start + n) % LS_FR_DEPTH];
        fprintf(stderr, "[minimm]   t-%u: opcode=0x%04x payload_len=%u avail=%u head=%02x%02x%02x%02x%s\n",
                depth - 1 - n, e->opcode, e->payload_len, e->avail_len,
                e->head[0], e->head[1], e->head[2], e->head[3],
                (n == depth - 1) ? "   <-- TRIGGER" : "");
    }
    g_ls->fr_tripped = 1;
    g_ls->fr_trip_seq = seen;
}

/*
 * observe-mode tracepoint: run the program purely for telemetry and NEVER change
 * flow. The program returns a sampled value (the frame opcode in the low byte)
 * the host histograms, plus an LS_FR_TRIGGER bit that arms the flight recorder.
 * This is eBPF observability reaching INSIDE the kernel-bypassing data plane —
 * exactly what kernel-based "eob" cannot see.
 */
int ls_request_eval_decision(const struct ls_ctx *ctx)
{
    if (!g_vm || !g_ls || g_ls->mode == LS_DISABLE)
        return LS_PASS;
    struct ls_ctx local = *ctx;
    uint64_t ret = 0;
    if (ubpf_exec(g_vm, &local, sizeof(local), &ret) == 0) {
        g_ls->trace[(ret & 0xff) & 7]++;   /* telemetry: histogram the sample */
        g_ls->hits++;                      /* total frames observed           */
        ls_fr_push(ctx);                   /* flight recorder: record run-up  */
        if ((ret & LS_FR_TRIGGER) && !g_ls->fr_tripped)
            ls_fr_dump("crash precondition at hook");   /* freeze + dump */
    }
    return LS_PASS;                        /* OBSERVE: traffic is never affected */
}
#else
int ls_request_eval_decision(const struct ls_ctx *ctx)
{
    if (!g_vm || !g_ls || g_ls->mode == LS_DISABLE)
        return LS_PASS;
    struct ls_ctx local = *ctx;            /* mutable copy = the VM's memory arg */
    uint64_t ret = 0;
    if (ubpf_exec(g_vm, &local, sizeof(local), &ret) != 0)
        return LS_PASS;                    /* VM error -> fail open */
    if (ret == 0)
        return LS_PASS;                    /* predicate did not match */
    g_ls->hits++;                          /* matched: evidence, always (§6) */
    g_ls->last_opcode = ctx->opcode;
    if (ret == 2) {                        /* match + enforce */
        g_ls->enforced++;
        return LS_DROP;                    /* host's sanctioned reject branch (§6.1) */
    }
    return LS_PASS;                        /* ret==1: match + monitor -> crash (§7.1) */
}
#endif

#else
/*
 * Track 1: reference shield compiled into the host. Same decision logic as the
 * eBPF shield, in plain C — proves the lifecycle with zero external runtime.
 */
__attribute__((noinline))
int ls_request_eval_decision(const struct ls_ctx *ctx)
{
    if (!g_ls || g_ls->mode == LS_DISABLE)
        return LS_PASS;

    if (matches_crash_precondition(ctx)) {
        g_ls->hits++;                      /* evidence: always counted (§6)  */
        g_ls->last_opcode = ctx->opcode;
        if (g_ls->mode == LS_ENFORCE) {
            g_ls->enforced++;
            return LS_DROP;                /* sanctioned reject branch (§6.1) */
        }
        /* LS_MONITOR: detected but NOT acted on -> falls through to crash (§7.1) */
    }
    return LS_PASS;
}
#endif

/* ----------------------------------------------------------------------- */
/* Relay plumbing (epoll bent pipe).                                        */
/* ----------------------------------------------------------------------- */

#define MAX_CONN 256
#define BUF_SZ   65536

struct conn {
    int fd;             /* this side's fd                          */
    int peer;           /* the other side's fd (the "bend")        */
    int is_client;      /* 1 = client->upstream side is inspected  */
    int in_use;
    uint8_t buf[BUF_SZ];
    size_t  have;       /* bytes buffered (for framing on client side) */
};
static struct conn g_conn[MAX_CONN];   /* indexed by fd */

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int dial(const char *hostport)
{
    char host[256]; const char *colon = strrchr(hostport, ':');
    if (!colon) return -1;
    size_t hlen = (size_t)(colon - hostport);
    if (hlen >= sizeof(host)) return -1;
    memcpy(host, hostport, hlen); host[hlen] = 0;

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host[0] ? host : "127.0.0.1", colon + 1, &hints, &res) != 0)
        return -1;
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) != 0) { close(fd); fd = -1; }
    freeaddrinfo(res);
    return fd;
}

static int listen_on(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { perror("bind"); close(fd); return -1; }
    if (listen(fd, 64) != 0) { perror("listen"); close(fd); return -1; }
    return fd;
}

static void conn_close_pair(int ep, int fd)
{
    if (fd < 0 || fd >= MAX_CONN || !g_conn[fd].in_use) return;
    int peer = g_conn[fd].peer;
    epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
    g_conn[fd].in_use = 0; close(fd);
    if (peer >= 0 && peer < MAX_CONN && g_conn[peer].in_use) {
        epoll_ctl(ep, EPOLL_CTL_DEL, peer, NULL);
        g_conn[peer].in_use = 0; close(peer);
    }
}

/* Inspect one buffered client->upstream frame; return verdict + frame fields.
 * Returns 1 if a full frame header was present and parsed, 0 otherwise. */
static int inspect_client_data(struct conn *c, enum ls_verdict *verdict_out)
{
    if (c->have < 4) { *verdict_out = LS_PASS; return 0; }   /* no header yet */
    uint16_t opcode = (uint16_t)((c->buf[0] << 8) | c->buf[1]);
    uint16_t plen   = (uint16_t)((c->buf[2] << 8) | c->buf[3]);

    struct ls_ctx ctx = {0};
    ctx.opcode = opcode;
    ctx.payload_len = plen;
    ctx.avail_len = (uint32_t)(c->have - 4 < plen ? c->have - 4 : plen);
    for (uint32_t i = 0; i < ctx.avail_len && i < sizeof(ctx.head); i++)
        ctx.head[i] = c->buf[4 + i];
    ctx.mode = g_ls ? (uint32_t)g_ls->mode : 0;   /* tell the shield the mode */

    int v = ls_request_eval_decision(&ctx);   /* <-- THE HOOK POINT */
    *verdict_out = (enum ls_verdict)v;

    /* On PASS, run the (vulnerable) parser before forwarding — as TMM would. */
    if (v == LS_PASS) {
        struct frame f = { opcode, plen, c->buf + 4 };
        process_frame(&f);   /* crashes here if opcode is OOB and unshielded */
    }
    return 1;
}

static int run_relay(int lport, const char *upstream)
{
    g_ls = ls_map_open(1);
    if (!g_ls) { perror("shm_open"); return 1; }

#if defined(LS_UBPF) || defined(LS_TRACE)
    {
        const char *obj = getenv("LS_SHIELD_OBJ");
        if (!obj) obj = "ls_shield_ubpf.bpf.o";
        if (ls_ubpf_init(obj) != 0)
            fprintf(stderr, "[minimm] WARNING: no shield loaded; passing through\n");
    }
#endif

    int lfd = listen_on(lport);
    if (lfd < 0) return 1;
    set_nonblock(lfd);

    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = lfd };
    epoll_ctl(ep, EPOLL_CTL_ADD, lfd, &ev);

    fprintf(stderr, "[minimm] relay :%d -> %s  (mode=%d, hook=%s)\n",
            lport, upstream, g_ls->mode, LS_HOOKPOINT_SYM);

    struct epoll_event events[64];
    for (;;) {
        int n = epoll_wait(ep, events, 64, -1);
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == lfd) {                       /* new client */
                int cfd = accept(lfd, NULL, NULL);
                if (cfd < 0 || cfd >= MAX_CONN) { if (cfd >= 0) close(cfd); continue; }
                int ufd = dial(upstream);
                if (ufd < 0 || ufd >= MAX_CONN) { close(cfd); if (ufd >= 0) close(ufd); continue; }
                set_nonblock(cfd); set_nonblock(ufd);
                int one = 1; setsockopt(ufd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

                g_conn[cfd] = (struct conn){ .fd=cfd, .peer=ufd, .is_client=1, .in_use=1 };
                g_conn[ufd] = (struct conn){ .fd=ufd, .peer=cfd, .is_client=0, .in_use=1 };
                struct epoll_event e1 = { .events=EPOLLIN, .data.fd=cfd };
                struct epoll_event e2 = { .events=EPOLLIN, .data.fd=ufd };
                epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &e1);
                epoll_ctl(ep, EPOLL_CTL_ADD, ufd, &e2);
                continue;
            }

            if (!g_conn[fd].in_use) continue;
            struct conn *c = &g_conn[fd];
            ssize_t r = read(fd, c->buf + c->have, BUF_SZ - c->have);
            if (r <= 0) { if (r == 0 || errno != EAGAIN) conn_close_pair(ep, fd); continue; }
            c->have += (size_t)r;

            if (c->is_client) {
                enum ls_verdict v = LS_PASS;
                inspect_client_data(c, &v);        /* eval + (maybe) crash here */
                if (v == LS_RESET) { conn_close_pair(ep, fd); continue; }
                if (v == LS_DROP)  { c->have = 0; continue; }   /* swallow frame */
                /* LS_PASS: forward raw bytes to upstream (the bent pipe) */
                ssize_t w = write(c->peer, c->buf, c->have); (void)w;
                c->have = 0;
            } else {
                /* upstream->client: transparent, no inspection */
                ssize_t w = write(c->peer, c->buf, c->have); (void)w;
                c->have = 0;
            }
        }
    }
}

/* ----------------------------------------------------------------------- */
/* echo upstream + ctl                                                      */
/* ----------------------------------------------------------------------- */

static int run_echo(int lport)
{
    int lfd = listen_on(lport);
    if (lfd < 0) return 1;
    fprintf(stderr, "[minimm] echo upstream :%d\n", lport);
    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) continue;
        uint8_t b[BUF_SZ]; ssize_t r;
        while ((r = read(c, b, sizeof(b))) > 0) { if (write(c, b, (size_t)r) < 0) break; }
        close(c);
    }
}

static int run_ctl(int argc, char **argv)
{
    struct ls_shared *s = ls_map_open(1);
    if (!s) { perror("shm_open"); return 1; }
    if (argc >= 2 && strcmp(argv[0], "mode") == 0) {
        int m = strcmp(argv[1], "enforce") == 0 ? LS_ENFORCE
              : strcmp(argv[1], "monitor") == 0 ? LS_MONITOR
              : strcmp(argv[1], "disable") == 0 ? LS_DISABLE : -1;
        if (m < 0) { fprintf(stderr, "mode: disable|monitor|enforce\n"); return 2; }
        s->mode = m;
        printf("mode = %s\n", argv[1]);
        return 0;
    }
    if (argc >= 1 && strcmp(argv[0], "stats") == 0) {
        const char *mn = s->mode==LS_ENFORCE?"enforce":s->mode==LS_MONITOR?"monitor":"disable";
        printf("mode=%s  hits=%llu  enforced=%llu  last_opcode=0x%04x  abi=%u\n",
               mn, (unsigned long long)s->hits, (unsigned long long)s->enforced,
               s->last_opcode, s->abi_version);
        printf("trace[opcode 0..7] =");
        for (int i = 0; i < 8; i++) printf(" %llu", (unsigned long long)s->trace[i]);
        printf("\n");
        return 0;
    }
    if (argc >= 1 && strcmp(argv[0], "flightrec") == 0) {
        /* Read the flight-recorder ring straight from shm — it SURVIVES a relay
         * crash, so this is the post-mortem view of the run-up (substrate §3.1). */
        uint64_t seen = s->fr_seen;
        uint32_t depth = seen < LS_FR_DEPTH ? (uint32_t)seen : LS_FR_DEPTH;
        printf("flight recorder: seen=%llu tripped=%u trip_seq=%llu depth=%u\n",
               (unsigned long long)seen, s->fr_tripped,
               (unsigned long long)s->fr_trip_seq, depth);
        uint32_t start = (s->fr_head + LS_FR_DEPTH - depth) % LS_FR_DEPTH;
        for (uint32_t n = 0; n < depth; n++) {
            struct ls_fr_entry *e = &s->fr_ring[(start + n) % LS_FR_DEPTH];
            printf("  t-%u: opcode=0x%04x payload_len=%u avail=%u head=%02x%02x%02x%02x%s\n",
                   depth - 1 - n, e->opcode, e->payload_len, e->avail_len,
                   e->head[0], e->head[1], e->head[2], e->head[3],
                   (s->fr_tripped && n == depth - 1) ? "   <-- TRIGGER" : "");
        }
        return 0;
    }
    fprintf(stderr, "ctl: mode {disable|monitor|enforce} | stats | flightrec\n");
    return 2;
}

/* ----------------------------------------------------------------------- */

static int arg_port(int argc, char **argv, const char *flag, int dflt)
{
    for (int i = 0; i < argc - 1; i++)
        if (strcmp(argv[i], flag) == 0) return atoi(argv[i+1]);
    return dflt;
}
static const char *arg_str(int argc, char **argv, const char *flag, const char *dflt)
{
    for (int i = 0; i < argc - 1; i++)
        if (strcmp(argv[i], flag) == 0) return argv[i+1];
    return dflt;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s relay --listen PORT --upstream HOST:PORT\n"
            "  %s echo  --listen PORT\n"
            "  %s ctl   mode {disable|monitor|enforce} | stats | flightrec\n", argv[0], argv[0], argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "relay") == 0)
        return run_relay(arg_port(argc-2, argv+2, "--listen", 8080),
                         arg_str(argc-2, argv+2, "--upstream", "127.0.0.1:9090"));
    if (strcmp(argv[1], "echo") == 0)
        return run_echo(arg_port(argc-2, argv+2, "--listen", 9090));
    if (strcmp(argv[1], "ctl") == 0)
        return run_ctl(argc - 2, argv + 2);
    fprintf(stderr, "unknown subcommand: %s\n", argv[1]);
    return 2;
}
