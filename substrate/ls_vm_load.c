/*
 * ls_vm_load.c --- load a program into a RUNNING TMM.
 *
 * This is the step that separates the demonstration from a patch. Rungs:
 *
 *   1. compiled in                 -> rebuild, repackage, redeploy
 *   2. LS_SHIELD_PATH at startup   -> no rebuild, but a restart
 *   3. THIS FILE                   -> no rebuild, no restart, no window
 *
 * =====================================================================
 *  WHAT THIS DELIBERATELY DOES NOT DO --- read before enabling it
 * =====================================================================
 *
 *  NO SIGNATURE VERIFICATION. `sig_verify()` is declared in shield_abi.h and
 *  has no implementation (scope item 4, deferred by decision). Anything that can
 *  reach this socket can put executable content into the data plane. That is why
 *  it is OFF unless LS_LOAD_SOCKET is set, why the socket is created 0600, and
 *  why every accepted load logs the fact that it was not verified. Do not let
 *  this reach a build anyone else runs.
 *
 *  NO RECLAMATION. A swapped-out VM is never freed. Freeing it requires knowing
 *  that no core is still executing it, which is the cross-core rendezvous of
 *  development-scope.md items 0b/0c and is not written. Leaking is the honest
 *  choice here: bounded by the number of loads, and it cannot corrupt anything.
 *  A load loop would eventually exhaust memory --- that is a real limit, stated
 *  rather than hidden.
 *
 *  NO SAFE POINT. The swap is a single atomic pointer store, which is why it is
 *  safe *enough* without one: a call in flight keeps using the VM it loaded at
 *  entry, and the next call picks up the new one. That gives atomic-per-call
 *  replacement, NOT the ordered cross-core publish item 0 specifies. For one
 *  hook and one program it is sufficient; for a multi-hook coordinated update it
 *  is not, and the difference is exactly item 0.
 *
 * The thread is a real design choice, not laziness: preparation --- create the
 * VM, read the ELF, check the O14 identity, JIT if asked --- is unbounded work
 * that must never happen on the poll loop. It happens here, and the poll loop
 * only ever sees a pointer that is either the old program or the new one.
 */

#include "ls_vm.h"
#include "ls_vm_config.h"
#include "shield_abi.h"

#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* Bounded so a malformed length field cannot make us allocate arbitrarily.
 * prog_len arrives from outside and is read before anything authenticates it,
 * which is the exact shape finding O8 was filed about --- so it is checked
 * against the bytes actually received, not trusted. */
#define LS_LOAD_MAX (1u << 20)

static pthread_t g_loader;
static int       g_loader_running;
static char      g_sock_path[108];

/* Provided by ls_vm.c: prepare a program into a spare slot and publish it over
 * an existing one with a single atomic store. */
extern int  ls_vm_reload(int slot, const void *elf, size_t elf_len,
                         const char *section, const char *function, enum ls_mode m);
extern void ls_vm_set_mode(int slot, enum ls_mode m);

static void
reply(int fd, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n > 0)
        (void)!write(fd, buf, (size_t)n);
}

static void
handle(int fd)
{
    /* Allocated per connection, not statically. A 1 MB static buffer is 1 MB of
     * permanently-resident .bss in EVERY TMM instance --- one per core --- to
     * receive a control message that arrives approximately never. Measured: the
     * static version grew .bss by 15.6%. The load path is off the data path, so
     * a malloc here costs nothing that matters. */
    unsigned char *g_load_buf = malloc(LS_LOAD_MAX);
    if (g_load_buf == NULL) {
        reply(fd, "ERR out of memory\n");
        return;
    }
    ssize_t n = read(fd, g_load_buf, LS_LOAD_MAX);

    if (n < (ssize_t)sizeof(struct shield_msg)) {
        reply(fd, "ERR short message (%ld bytes)\n", (long)n);
        free(g_load_buf);
        return;
    }

    struct shield_msg *m = (struct shield_msg *)g_load_buf;

    /* O8: prog_len is attacker-influenced and is read before authentication.
     * There is no authentication here at all, so the length check is the only
     * thing standing between a bad field and a bad read. Check it against what
     * actually arrived. */
    size_t hdr = sizeof(struct shield_msg);
    if (m->prog_len > (size_t)n - hdr) {
        reply(fd, "ERR prog_len %u exceeds received payload %lu\n",
              m->prog_len, (unsigned long)((size_t)n - hdr));
        free(g_load_buf);
        return;
    }

    /* O14, on real code: the binding carries ONE identity --- `hook` --- and the
     * loader needs two, because PREVAIL proved a SECTION and uBPF runs a SYMBOL.
     * Both are synthesised here by convention (section = "fentry/<hook>",
     * function = "shield"), and a convention is exactly what O14 says is not good
     * enough: nothing signed commits to either name, so the identity check in
     * ls_vm_arm is verifying the program against names this loader made up
     * rather than against names an authority asserted. The binding needs both
     * fields. Until it has them, this is the gap, not a detail. */
    char section[96];
    snprintf(section, sizeof section, "fentry/%.63s", m->binding.hook);

    switch (m->op) {
    case SHIELD_OP_LOAD: {
        fprintf(stderr,
                "ls_vm: LOAD accepted on %s --- NOT SIGNATURE VERIFIED "
                "(scope item 4 deferred); hook=%.63s bytes=%u\n",
                g_sock_path, m->binding.hook, m->prog_len);
        int slot = ls_vm_reload(0, m->prog, m->prog_len,
                                section, "shield", (enum ls_mode)m->mode);
        if (slot < 0)
            reply(fd, "ERR load refused (identity mismatch, malformed ELF, or "
                      "uBPF rejected it)\n");
        else
            reply(fd, "OK loaded slot=%d mode=%d unverified=yes\n", slot, m->mode);
        break;
    }
    case SHIELD_OP_SET_MODE:
        ls_vm_set_mode(0, (enum ls_mode)m->mode);
        reply(fd, "OK mode=%d\n", m->mode);
        break;

    case SHIELD_OP_STATUS: {
        struct ls_stats st;
        if (!ls_vm_stats(0, &st)) { reply(fd, "ERR no such slot\n"); break; }
        reply(fd, "OK armed=%d mode=%d fired=%llu safe_returns=%llu errors=%llu "
                  "cycles=%llu cycles_max=%llu\n",
              (int)st.armed, st.mode,
              (unsigned long long)st.fired, (unsigned long long)st.safe_returns,
              (unsigned long long)st.errors, (unsigned long long)st.cycles,
              (unsigned long long)st.cycles_max);
        break;
    }
    case SHIELD_OP_REVOKE:
        /* Disarm is the honest half of revocation. The other half --- reclaiming
         * the program's memory --- needs item 0c. Mode DISABLE stops it running;
         * it does not remove it. */
        ls_vm_set_mode(0, LS_MODE_DISABLE);
        reply(fd, "OK disabled (not reclaimed --- see item 0c)\n");
        break;

    default:
        reply(fd, "ERR unknown op %d\n", m->op);
    }
    free(g_load_buf);
}

static void *
loader_thread(void *arg)
{
    (void)arg;
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) {
        fprintf(stderr, "ls_vm: loader socket(): %s\n", strerror(errno));
        return NULL;
    }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", g_sock_path);
    unlink(g_sock_path);

    /* 0600 before anyone can connect: the bind inherits the umask, so set it
     * rather than assume it. This is containment, not authentication --- it
     * limits who can reach an unauthenticated load path to whoever shares the
     * uid, which in this container is root. */
    mode_t old = umask(0177);
    int rc = bind(srv, (struct sockaddr *)&sa, sizeof sa);
    umask(old);
    if (rc < 0 || listen(srv, 4) < 0) {
        fprintf(stderr, "ls_vm: loader bind/listen %s: %s\n", g_sock_path, strerror(errno));
        close(srv);
        return NULL;
    }

    fprintf(stderr,
            "ls_vm: LOADER LISTENING on %s --- accepts UNVERIFIED programs. "
            "This must not exist in a build anyone else runs.\n", g_sock_path);

    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        handle(fd);
        close(fd);
    }
    close(srv);
    return NULL;
}

/* Called from init, off the data path. No socket unless asked for. */
void
ls_vm_loader_start(void)
{
    const char *p = getenv("LS_LOAD_SOCKET");
    if (p == NULL || *p == '\0')
        return;                      /* default: no load path at all */
    if (g_loader_running)
        return;
    snprintf(g_sock_path, sizeof g_sock_path, "%s", p);
    if (pthread_create(&g_loader, NULL, loader_thread, NULL) != 0) {
        fprintf(stderr, "ls_vm: could not start loader thread\n");
        return;
    }
    pthread_detach(g_loader);
    g_loader_running = 1;
}
