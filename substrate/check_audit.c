/* check_audit.c --- the audit trail, attacked.
 *
 * An audit trail nobody has tried to corrupt is a log file with ambitions. So this is not "does
 * it print something": it is the list of ways a record could be wrong, each one executed.
 *
 *   A1  the record exists at all, one line per operation, terminated
 *   A2  seq increases by exactly one and never repeats --- a gap must mean a deleted record
 *   A3  peer credentials come from the KERNEL, not from the message: the pid recorded is the
 *       pid that actually connected. Asserted against getpid() over a socketpair
 *   A4  the verdict is the reply VERBATIM, so the record cannot disagree with what was said
 *   A5  a hook name containing a newline, a quote or spaces cannot forge a second record ---
 *       log injection, the oldest attack on an audit trail
 *   A6  an uninterpretable message is still recorded, because malformed traffic must not be
 *       the one thing that leaves no trace
 *   A7  an over-long verdict is truncated VISIBLY, never spliced into the following record
 *   A8  the build ID recorded is this binary's real GNU build ID --- the same string the arming
 *       gate compares --- and not a compile timestamp
 *
 * WHAT THIS CANNOT TEST, and it is the important half: durability. The primary sink is stderr
 * because in the deployment that is the container's log stream, collected by something TMM
 * cannot write to. Nothing here proves that collector exists. This test writes to a FILE sink,
 * which is the weaker one on purpose, and the file's weakness (TMM can truncate it) is precisely
 * why it is not the sink relied on.
 */
#include "ls_audit.h"
#include "shield_abi.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails;

static void ok(const char *what, int cond)
{
    printf("  %-62s %s\n", what, cond ? "ok" : "FAIL");
    if (!cond) fails++;
}

/* Read the whole sink back. Small by construction --- a handful of records. */
static size_t slurp(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) n = 0;
    buf[n] = '\0';
    return (size_t)n;
}

static const char *field(const char *line, const char *key, char *out, size_t out_len)
{
    out[0] = '\0';
    const char *p = strstr(line, key);
    if (p == NULL) return out;
    p += strlen(key);
    size_t o = 0;
    while (*p != '\0' && *p != ' ' && *p != '\n' && o + 1 < out_len) out[o++] = *p++;
    out[o] = '\0';
    return out;
}

static unsigned long long count_lines(const char *s, const char *prefix)
{
    unsigned long long n = 0;
    for (const char *p = s; (p = strstr(p, prefix)) != NULL; p += strlen(prefix)) n++;
    return n;
}

int main(void)
{
    char path[] = "/tmp/ls_audit_check.XXXXXX";
    int tfd = mkstemp(path);
    if (tfd < 0) { perror("mkstemp"); return 1; }
    close(tfd);
    setenv("LS_AUDIT_PATH", path, 1);

    printf("audit sink: %s\n\n", path);
    ls_audit_init();

    /* A socketpair gives a connected AF_UNIX socket whose peer is THIS process, so the pid the
     * kernel reports through SO_PEERCRED is one this test knows independently. That is what
     * makes A3 an assertion rather than an observation. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }

    struct shield_msg m;
    memset(&m, 0, sizeof m);
    m.op       = SHIELD_OP_LOAD;
    m.epoch    = 5;
    m.mode     = 1;
    m.prog_len = 4432;
    snprintf(m.binding.hook, sizeof m.binding.hook, "http_parse_client_headers");
    for (int i = 0; i < 8; i++) m.binding.prog_sha256[i] = (unsigned char)(0x10 * i + i);
    m.binding.build_min    = 100;
    m.binding.build_max    = 200;
    m.binding.mode_ceiling = 2;
    m.binding.expires_with = 7;

    unsigned long long before = ls_audit_count();
    ls_audit_op(sv[0], &m, "OK loaded slot=5 mode=1 signature=verified\n");
    ls_audit_op(sv[0], &m, "ERR load refused (identity mismatch)\n");
    ok("A1  two operations produced two records",
       ls_audit_count() == before + 2);

    char buf[16384];
    size_t n = slurp(path, buf, sizeof buf);
    ok("A1  the sink is non-empty", n > 0);
    ok("A1  every record is one line, newline-terminated",
       n > 0 && buf[n - 1] == '\n' && count_lines(buf, "ls_audit: seq=") == 2);

    /* A2 --- sequence numbers, in order, no repeats. */
    char s1[32], s2[32];
    char *l1 = strstr(buf, "ls_audit: seq=");
    char *l2 = l1 ? strstr(l1 + 1, "ls_audit: seq=") : NULL;
    field(l1 ? l1 : "", "seq=", s1, sizeof s1);
    field(l2 ? l2 : "", "seq=", s2, sizeof s2);
    ok("A2  seq increases by exactly one",
       l1 && l2 && atoll(s2) == atoll(s1) + 1);

    /* A3 --- the kernel's answer, checked against one this test already knows. */
    char pid[32];
    field(l1 ? l1 : "", "peer_pid=", pid, sizeof pid);
    ok("A3  peer_pid is the pid that actually connected (kernel-attested)",
       atoi(pid) == (int)getpid());
    char uid[32];
    field(l1 ? l1 : "", "peer_uid=", uid, sizeof uid);
    ok("A3  peer_uid is this process's uid",
       atoi(uid) == (int)getuid());

    /* A4 --- the verdict is the reply VERBATIM, which is what ls_audit.h promises. The first
     * version of this assertion expected `verdict=OK_loaded_slot=5` and failed: the field was
     * being run through the hook-name sanitiser, which turns spaces and '=' into underscores, so
     * the record held a paraphrase of the reply rather than the reply. Quoting the field and
     * putting it last fixed the code; this assertion is what found it. */
    ok("A4  the admitted record holds the OK reply verbatim",
       l1 && strstr(l1, "verdict=\"OK loaded slot=5 mode=1 signature=verified") != NULL);
    ok("A4  the refused record holds the ERR reply verbatim",
       l2 && strstr(l2, "verdict=\"ERR load refused (identity mismatch)") != NULL);
    ok("A4  a refusal is never recorded as an OK",
       l2 && strstr(l2, "verdict=\"OK") == NULL);

    /* A5 --- log injection. A hook name carrying a newline and a forged prefix must not become
     * a second record, and must not break the field structure of the first. */
    unsigned long long lines_before = count_lines(buf, "ls_audit: seq=");
    struct shield_msg evil = m;
    memcpy(evil.binding.hook,
           "x\nls_audit: seq=999 op=ARM verdict=OK_FORGED\n", 45);
    ls_audit_op(sv[0], &evil, "ERR arm refused\n");
    n = slurp(path, buf, sizeof buf);
    ok("A5  an injected newline does not create an extra record",
       count_lines(buf, "ls_audit: seq=") == lines_before + 1);
    ok("A5  the forged verdict never appears",
       strstr(buf, "verdict=OK_FORGED") == NULL && strstr(buf, "verdict=\"OK_FORGED") == NULL);
    ok("A5  the injected text survives as inert, escaped characters",
       strstr(buf, "hook=x_ls_audit:") != NULL);

    /* A9 --- the ops this trail exists for must be NAMED, not numbered. The first live run
     * recorded ARM and DISARM as op_4099 and op_4100, so the one record a reader would go looking
     * for --- who armed what --- was the one that did not say what it was. */
    struct shield_msg armed = m;
    armed.op = 0x1003;
    ls_audit_op(sv[0], &armed, "OK ARMED LIVE entry=0x1451184 slot=5 (no restart)\n");
    armed.op = 0x1004;
    ls_audit_op(sv[0], &armed, "OK DISARMED LIVE entry=0x1451184\n");
    n = slurp(path, buf, sizeof buf);
    ok("A9  ARM is recorded as op=ARM, not as a number",
       strstr(buf, "op=ARM ") != NULL && strstr(buf, "op=op_4099") == NULL);
    ok("A9  DISARM likewise",
       strstr(buf, "op=DISARM ") != NULL && strstr(buf, "op=op_4100") == NULL);

    /* A6 --- garbage in is still evidence. */
    lines_before = count_lines(buf, "ls_audit: seq=");
    ls_audit_op(sv[0], NULL, "ERR short message (3 bytes)\n");
    n = slurp(path, buf, sizeof buf);
    ok("A6  an uninterpretable message is recorded, as MALFORMED",
       count_lines(buf, "ls_audit: seq=") == lines_before + 1 &&
       strstr(buf, "op=MALFORMED") != NULL);

    /* A7 --- an over-long verdict must be cut visibly, not spliced into the next record. */
    char huge[2048];
    memset(huge, 'A', sizeof huge - 2);
    huge[sizeof huge - 2] = '\n';
    huge[sizeof huge - 1] = '\0';
    lines_before = count_lines(buf, "ls_audit: seq=");
    ls_audit_op(sv[0], &m, huge);
    n = slurp(path, buf, sizeof buf);
    ok("A7  an over-long record is still exactly one record",
       count_lines(buf, "ls_audit: seq=") == lines_before + 1);
    ok("A7  ... and says so rather than being silently cut",
       strstr(buf, "[CUT]") != NULL || strstr(buf, "TRUNCATED") != NULL);
    ok("A7  ... and is still newline-terminated, so the next record starts clean",
       n > 0 && buf[n - 1] == '\n');

    /* A8 --- the build ID is this binary's, and it is a build ID rather than a timestamp. It is
     * legitimate for a binary to have none (no --build-id at link time), so the assertion is
     * conditional on the linker having emitted one --- which is checked independently, by
     * looking for the note with the same tool the rest of the pipeline uses. */
    const char *bid = ls_audit_build_id();
    int hexish = 1, len = (int)strlen(bid);
    for (int i = 0; i < len; i++)
        if (!((bid[i] >= '0' && bid[i] <= '9') || (bid[i] >= 'a' && bid[i] <= 'f'))) hexish = 0;
    printf("  build id read: %s (%d chars)\n", bid, len);
    if (strcmp(bid, "unknown") == 0) {
        printf("  A8  SKIPPED --- this test binary carries no GNU build-id note.\n");
        printf("      Not a pass. The Makefile links it with --build-id so this should not\n");
        printf("      happen; if it does, the parse is untested rather than proven.\n");
        fails++;   /* an untested parse in an audit trail is a failure, not a skip */
    } else {
        ok("A8  the build id is hex", hexish);
        ok("A8  ... and is 16 or 20 bytes, the only sizes gcc/lld emit",
           len == 32 || len == 40);
        ok("A8  ... and the record carries the same string the accessor returns",
           strstr(buf, bid) != NULL);
    }

    close(sv[0]);
    close(sv[1]);

    /* Show one record, because a format nobody reads is a format nobody notices is wrong. */
    if (l1 != NULL) {
        char one[1200];
        snprintf(one, sizeof one, "%s", l1);
        char *nl = strchr(one, '\n'); if (nl) *nl = '\0';
        printf("\n  sample record:\n    %s\n", one);
    }

    unlink(path);
    printf("\n%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
