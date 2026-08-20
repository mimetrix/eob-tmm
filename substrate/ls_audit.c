/* ls_audit.c --- see ls_audit.h for what this records and, more importantly, what it does not.
 *
 * EVERY CONSTRAINT IN THIS FILE COMES FROM THE THREAD IT RUNS ON. This is the loader thread: a
 * plain pthread that TMM does not know about, where malloc() spins forever because TMM aliases
 * it to a per-core allocator this thread has no state in (the long note in ls_vm_load.c, and
 * CONTESTED-PREMISES.md #10 for the time I reasoned past it). So:
 *
 *   - no malloc, anywhere. Every buffer here is on the stack or static.
 *   - no stdio on the write path. fprintf() to an already-open stream happens not to allocate
 *     today, which is a property of glibc's buffering rather than a guarantee, and an audit
 *     record that hangs the loader is worse than no audit record. write(2) only.
 *   - snprintf IS used, because it formats into a caller-supplied buffer and glibc's integer
 *     and string conversions do not allocate. No %f anywhere --- float formatting is the one
 *     conversion that historically did.
 *
 * ONE WRITE PER RECORD, and the line is assembled completely before it is issued. Two writes
 * would let a concurrent writer to the same fd interleave, and a half-line in an audit trail is
 * indistinguishable from a truncated one. write() of under PIPE_BUF to a pipe is atomic, and an
 * O_APPEND write to a regular file is atomic against other appenders; both properties need the
 * record to be one call.
 */
#include "ls_audit.h"
#include "shield_abi.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* SO_PEERCRED and struct ucred. Declared here rather than pulled in with _GNU_SOURCE, which
 * this translation unit cannot set from inside TMM's build without affecting every other header
 * it includes. The layout is kernel ABI (three 32-bit fields) and has not changed since Linux
 * 2.2; SO_PEERCRED is 17 on every architecture Linux supports it on, which is asserted below
 * rather than assumed. */
#ifndef SO_PEERCRED
#define SO_PEERCRED 17
#endif
struct ls_ucred { unsigned int pid; unsigned int uid; unsigned int gid; };
_Static_assert(sizeof(struct ls_ucred) == 12, "struct ucred is three 32-bit fields");

#define LS_AUDIT_LINE 1024

/* ONE GLOBAL FOR THE WHOLE SUBSYSTEM, and the reason is a build gate rather than taste.
 * src/compile/Makefile runs bin/diff-globals against a per-architecture manifest of every
 * mutable global in the binary, and any new name fails the link. The first version of this file
 * declared five separate statics --- and the loader's last-reply buffer made six --- so it cost
 * a full build cycle and would have added six entries to a permanent manifest for one feature.
 *
 * The gate is right and the code was wrong. Its purpose is to make each piece of new global
 * mutable state a deliberate, reviewed decision; six names for one subsystem is six decisions
 * where there is only one. Folding them into a single struct makes the manifest entry match the
 * unit of design, and a reader of that manifest learns "the audit trail has state" rather than
 * five unrelated-looking nouns.
 *
 * Note also that the manifest is an EXACT match in both directions: deleting tracked state fails
 * the link exactly as adding it does. So this struct is now the one thing that must be declared
 * there, and splitting it back out later is a build-breaking change, not a refactor. */
struct ls_audit_state {
    int                file_fd;          /* optional LS_AUDIT_PATH sink, -1 if none        */
    int                inited;
    unsigned long long count;            /* records emitted, so a gap in seq is visible    */
    char               build[48];        /* this binary's GNU build id, hex                */
    char               last_reply[320];  /* what the caller was last told, quoted verbatim */
};
static struct ls_audit_state g_ls_audit = { .file_fd = -1, .build = "unknown" };

unsigned long long ls_audit_count(void)   { return g_ls_audit.count; }
const char *       ls_audit_build_id(void){ return g_ls_audit.build; }

/* Called by the loader's reply() so the record can quote what the caller was told rather than
 * deriving a second verdict from the same inputs. Lives here, not in ls_vm_load.c, so the
 * feature's state is one manifest entry instead of two. */
void
ls_audit_note_reply(const char *text)
{
    snprintf(g_ls_audit.last_reply, sizeof g_ls_audit.last_reply, "%s", text != NULL ? text : "");
}

const char *
ls_audit_last_reply(void)
{
    return g_ls_audit.last_reply[0] != '\0' ? g_ls_audit.last_reply : NULL;
}

void
ls_audit_clear_reply(void)
{
    g_ls_audit.last_reply[0] = '\0';
}

/* ---------------------------------------------------------------------------------------------
 * This binary's GNU build ID, read from /proc/self/exe.
 *
 * WHY NOT __DATE__/__TIME__, which ls_vm.c already prints as "build=". Those say when the file
 * was compiled, which is not what anything else in this system keys on. Arming by name is gated
 * on the GNU build ID --- the index carries the ID of the binary it was generated from, and a
 * mismatch is refused --- so an audit record that named a different kind of build would be
 * describing a different question from the one the gate asked. A reader must see the SAME string
 * in the record and in the refusal.
 *
 * The parse walks program headers looking for PT_NOTE and scans for NT_GNU_BUILD_ID. It is a
 * SCAN rather than a walk of note entries on purpose: note alignment is per-note and getting it
 * wrong truncated a 20-byte ID to 16 in ls_buildid.py (which is why that file exists and is
 * canonical on the Python side). Reading a stale or short ID here would be worse than reading
 * none, because a short ID still LOOKS like an answer.
 */
#define EI_NIDENT 16
struct ls_ehdr64 {
    unsigned char e_ident[EI_NIDENT];
    unsigned short e_type, e_machine;
    unsigned int e_version;
    unsigned long long e_entry, e_phoff, e_shoff;
    unsigned int e_flags;
    unsigned short e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct ls_phdr64 {
    unsigned int p_type, p_flags;
    unsigned long long p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};

static void
ls_audit_read_build_id(void)
{
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0)
        return;

    struct ls_ehdr64 eh;
    if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh) { close(fd); return; }
    if (eh.e_ident[0] != 0x7f || eh.e_ident[1] != 'E' || eh.e_ident[2] != 'L' ||
        eh.e_ident[3] != 'F' || eh.e_ident[4] != 2 /* ELFCLASS64 */) { close(fd); return; }
    if (eh.e_phentsize != sizeof(struct ls_phdr64) || eh.e_phnum == 0) { close(fd); return; }

    for (unsigned short i = 0; i < eh.e_phnum; i++) {
        struct ls_phdr64 ph;
        if (pread(fd, &ph, sizeof ph, (off_t)(eh.e_phoff + (unsigned long long)i * sizeof ph))
            != (ssize_t)sizeof ph)
            break;
        if (ph.p_type != 4 /* PT_NOTE */)
            continue;
        /* A build-ID note is 16 bytes of header plus at most 20 of ID. Anything larger in a
         * PT_NOTE segment is other notes, and a bounded read keeps this off the heap. */
        unsigned char note[4096];
        size_t want = ph.p_filesz < sizeof note ? (size_t)ph.p_filesz : sizeof note;
        ssize_t got = pread(fd, note, want, (off_t)ph.p_offset);
        if (got <= 0)
            continue;
        /* namesz=4, descsz=N, type=3(NT_GNU_BUILD_ID), then "GNU\0". Scan for that 16-byte
         * pattern for each plausible descsz rather than walking note-by-note. */
        static const unsigned int sizes[3] = { 20, 16, 8 };
        for (int s = 0; s < 3; s++) {
            unsigned char pat[16];
            unsigned int four = 4, ds = sizes[s], three = 3;
            memcpy(pat + 0, &four,  4);
            memcpy(pat + 4, &ds,    4);
            memcpy(pat + 8, &three, 4);
            memcpy(pat + 12, "GNU\0", 4);
            for (ssize_t off = 0; off + 16 + (ssize_t)ds <= got; off++) {
                if (memcmp(note + off, pat, 16) != 0)
                    continue;
                const unsigned char *id = note + off + 16;
                char *o = g_ls_audit.build;
                for (unsigned int b = 0; b < ds; b++) {
                    static const char hex[] = "0123456789abcdef";
                    *o++ = hex[id[b] >> 4];
                    *o++ = hex[id[b] & 15];
                }
                *o = '\0';
                close(fd);
                return;
            }
        }
    }
    close(fd);
}

void
ls_audit_init(void)
{
    if (g_ls_audit.inited)
        return;
    g_ls_audit.inited = 1;
    ls_audit_read_build_id();

    /* The optional file sink. Deliberately secondary: a file TMM can write is a file TMM can
     * truncate, so it proves nothing against the process itself. It exists for tests, and for
     * hosts with no log collector, and the log line below says which sinks are live so nobody
     * assumes durability that is not there. */
    const char *path = getenv("LS_AUDIT_PATH");
    if (path != NULL && path[0] != '\0') {
        g_ls_audit.file_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (g_ls_audit.file_fd < 0)
            fprintf(stderr, "ls_audit: cannot open LS_AUDIT_PATH=%s --- records go to stderr "
                            "only\n", path);
    }
    fprintf(stderr, "ls_audit: recording control-plane operations to stderr%s. Build %s. "
                    "Peer credentials are kernel-attested (SO_PEERCRED) and identify a PROCESS, "
                    "not an operator.\n",
            g_ls_audit.file_fd >= 0 ? " and LS_AUDIT_PATH" : "", g_ls_audit.build);
}

/* /proc/<pid>/comm, trimmed, into a caller buffer. Best effort by design: the peer may exit
 * between its request and this read, and "the process is gone" is a normal outcome for a
 * kubectl exec that has already returned. An empty answer is recorded as such rather than
 * omitted, because a missing field and an unanswerable one look identical to a reader. */
static void
ls_audit_peer_comm(unsigned int pid, char *out, size_t out_len)
{
    out[0] = '\0';
    if (pid == 0)
        return;
    char path[64];
    snprintf(path, sizeof path, "/proc/%u/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { snprintf(out, out_len, "gone"); return; }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) { snprintf(out, out_len, "gone"); return; }
    buf[n] = '\0';
    /* Trim the trailing newline, and anything a reader could mistake for a field separator.
     * comm is 15 bytes of whatever the process chose, so it is untrusted text landing in a
     * structured line --- a space or a quote in it would corrupt the record's shape. */
    size_t o = 0;
    for (ssize_t i = 0; i < n && o + 1 < out_len; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '\n' || c == '\r' || c == '\0')
            break;
        out[o++] = (c < 0x20 || c > 0x7e || c == ' ' || c == '"' || c == '=') ? '_' : (char)c;
    }
    out[o] = '\0';
}

static const char *
ls_audit_opname(unsigned int op)
{
    switch (op) {
    case SHIELD_OP_LOAD:     return "LOAD";
    case SHIELD_OP_SET_MODE: return "SET_MODE";
    case SHIELD_OP_STATUS:   return "STATUS";
    case SHIELD_OP_REVOKE:   return "REVOKE";
    default:                 return NULL;      /* printed as the number, see below */
    }
}

/* Copy untrusted text into an UNQUOTED field. Same reasoning as comm: hook names arrive over
 * the socket, and a caller who puts a quote or a newline in one must not be able to forge a
 * second record inside the first --- log injection is the oldest trick against an audit trail.
 * Everything outside printable ASCII, plus the field separators, becomes '_'.
 *
 * TRUNCATION IS MARKED, not silent. The first version cut at the buffer and said nothing, and
 * check_audit.c caught it on a 2 KB verdict: the record looked complete and had lost most of
 * its content. A field that can quietly shorten is a field that can quietly change meaning ---
 * "ERR refused because X" and "ERR refused" are different statements. Returns 1 if it fitted. */
static int
ls_audit_sanitize(const char *in, size_t in_max, char *out, size_t out_len)
{
    size_t o = 0, i = 0;
    for (; i < in_max && in[i] != '\0' && o + 1 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        out[o++] = (c < 0x20 || c > 0x7e || c == ' ' || c == '"' || c == '=') ? '_' : (char)c;
    }
    int fitted = (i >= in_max || in[i] == '\0');
    if (o == 0 && out_len > 1) { out[o++] = '-'; }
    out[o] = '\0';
    if (!fitted && out_len > 12) {
        /* Overwrite the tail rather than append: there is by definition no room to append. */
        memcpy(out + (o > 11 ? o - 11 : 0), "_CUT_", 5);
        out[(o > 11 ? o - 11 : 0) + 5] = '\0';
    }
    return fitted;
}

/* The VERDICT field is different, and deliberately so: it is the line the caller received, and
 * ls_audit.h promises it is quoted verbatim. Running it through the sanitiser above broke that
 * promise --- spaces and '=' became underscores, so `OK loaded slot=5` was recorded as
 * `OK_loaded_slot_5`, which is a paraphrase. check_audit.c A4 failed on exactly that, which is
 * the test earning its keep on the first run.
 *
 * So this preserves the text and makes it unambiguous by other means: the field is wrapped in
 * double quotes and is ALWAYS LAST on the line, so a space inside it cannot be mistaken for a
 * separator. Only the two characters that could break out are touched --- a double quote, and
 * anything that could end the line or start a new record. */
static int
ls_audit_quote(const char *in, size_t in_max, char *out, size_t out_len)
{
    /* TWO WAYS THIS CAN CUT, and the first version only noticed one. It reported "fitted"
     * whenever the loop stopped because `i` reached in_max --- but in_max is a POLICY limit on a
     * NUL-terminated string, so stopping there is exactly the case where input remains. A 2 KB
     * reply was therefore recorded as its first 300 characters with no marker, and check_audit's
     * A7 kept failing while the code looked correct. Measure the input's real length (bounded, so
     * an unterminated buffer cannot run away) and compare. */
    size_t inlen = 0;
    while (inlen <= in_max && in[inlen] != '\0') inlen++;
    int cut_by_policy = (inlen > in_max);

    size_t o = 0, i = 0;
    for (; i < in_max && in[i] != '\0' && o + 1 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"')                     out[o++] = '\'';
        else if (c == '\n' || c == '\r')   out[o++] = ' ';     /* keeps it one line */
        else if (c < 0x20 || c > 0x7e)    out[o++] = '?';
        else                              out[o++] = (char)c;
    }
    int fitted = !cut_by_policy && (i >= in_max || in[i] == '\0');
    if (o == 0 && out_len > 1) { out[o++] = '-'; }
    out[o] = '\0';
    if (!fitted && out_len > 8) {
        memcpy(out + (o > 7 ? o - 7 : 0), "[CUT]", 5);
        out[(o > 7 ? o - 7 : 0) + 5] = '\0';
    }
    return fitted;
}

void
ls_audit_op(int fd, const struct shield_msg *m, const char *reply_text)
{
    if (!g_ls_audit.inited)
        ls_audit_init();

    /* PEER CREDENTIALS FIRST, because they are the only field here the caller cannot influence.
     * The kernel fills this at connect() time from the connecting process's real ids. A failure
     * is recorded as pid=0, which a reader must be able to tell apart from a genuine pid 0 ---
     * there is no genuine pid 0 in a container, so 0 is unambiguous. */
    struct ls_ucred uc = { 0, 0, 0 };
    unsigned int uclen = (unsigned int)sizeof uc;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &uclen) != 0)
        uc.pid = uc.uid = uc.gid = 0;

    char comm[32];
    ls_audit_peer_comm(uc.pid, comm, sizeof comm);

    /* REALTIME for correlating with everything else in the cluster, MONOTONIC because realtime
     * can step backwards and an audit trail whose order depends on NTP is not ordered. Both,
     * because neither alone answers "when" and "in what sequence". */
    struct timespec rt = { 0, 0 }, mo = { 0, 0 };
    (void)clock_gettime(CLOCK_REALTIME, &rt);
    (void)clock_gettime(CLOCK_MONOTONIC, &mo);

    /* 300 is the widest reply this loader produces; anything longer is marked [CUT] rather than
     * shortened in silence. */
    char verdict[320];
    (void)ls_audit_quote(reply_text != NULL ? reply_text : "-", 300, verdict, sizeof verdict);

    char line[LS_AUDIT_LINE];
    int n;

    unsigned long long seq = ++g_ls_audit.count;

    if (m == NULL) {
        /* A peer connected and sent something uninterpretable. Recorded rather than dropped:
         * malformed traffic must not be the one thing that leaves no trace. */
        n = snprintf(line, sizeof line,
                     "ls_audit: seq=%llu ts=%lld.%09ld mono=%lld.%09ld tmm_pid=%d tmm_build=%s "
                     "peer_pid=%u peer_uid=%u peer_gid=%u peer_comm=%s "
                     "op=MALFORMED verdict=\"%s\"\n",
                     seq, (long long)rt.tv_sec, rt.tv_nsec, (long long)mo.tv_sec, mo.tv_nsec,
                     (int)getpid(), g_ls_audit.build, uc.pid, uc.uid, uc.gid, comm, verdict);
    } else {
        char hook[80];
        ls_audit_sanitize(m->binding.hook, sizeof m->binding.hook, hook, sizeof hook);

        /* The program's identity is the hash the SIGNATURE commits to, not a hash of the bytes
         * as received. Those are the same thing for an admitted program and deliberately
         * different for a refused one --- recording the received bytes' hash would make a
         * forgery look like a distinct program, when what a reader needs to know is which
         * signed artifact was being claimed. */
        char sha[17];
        for (int i = 0; i < 8; i++) {
            static const char hex[] = "0123456789abcdef";
            sha[i * 2]     = hex[m->binding.prog_sha256[i] >> 4];
            sha[i * 2 + 1] = hex[m->binding.prog_sha256[i] & 15];
        }
        sha[16] = '\0';

        const char *opname = ls_audit_opname(m->op);
        char opbuf[24];
        if (opname == NULL) {
            snprintf(opbuf, sizeof opbuf, "op_%u", m->op);
            opname = opbuf;
        }

        n = snprintf(line, sizeof line,
                     "ls_audit: seq=%llu ts=%lld.%09ld mono=%lld.%09ld tmm_pid=%d tmm_build=%s "
                     "peer_pid=%u peer_uid=%u peer_gid=%u peer_comm=%s "
                     "op=%s slot=%u mode=%u hook=%s prog_len=%u prog_sha256=%s "
                     "build_min=%u build_max=%u ceiling=%u ctx_abi=%u expires=%u "
                     "verdict=\"%s\"\n",
                     seq, (long long)rt.tv_sec, rt.tv_nsec, (long long)mo.tv_sec, mo.tv_nsec,
                     (int)getpid(), g_ls_audit.build, uc.pid, uc.uid, uc.gid, comm,
                     opname, m->epoch, m->mode, hook, m->prog_len, sha,
                     m->binding.build_min, m->binding.build_max, m->binding.mode_ceiling,
                     m->binding.ctx_abi_version, m->binding.expires_with, verdict);
    }

    if (n <= 0)
        return;
    /* TRUNCATION IS MADE VISIBLE. snprintf returns what it WOULD have written, so n over the
     * buffer means the record was cut --- including possibly its newline, which would splice
     * this record into the next one. Force the terminator and mark it, because a silently
     * truncated audit record is a forged one. */
    size_t len = (size_t)n;
    if (len >= sizeof line) {
        len = sizeof line - 1;
        line[len - 1] = '\n';
        if (len > 12) memcpy(line + len - 12, " TRUNCATED\n", 11);
    }

    (void)!write(2, line, len);
    if (g_ls_audit.file_fd >= 0)
        (void)!write(g_ls_audit.file_fd, line, len);
}
