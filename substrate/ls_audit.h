/* ls_audit.h --- one durable record per control-plane operation: who asked, for what, and
 * what they were told.
 *
 * THE GAP THIS CLOSES is the one GROUND_TRUTH.md has carried as ROADMAP since the loader
 * existed: "nothing durably records who armed what, when, against which build". Every other
 * gate in this substrate decides whether an operation is ALLOWED. None of them leaves a trace
 * that it happened. After signature verification landed on 2026-08-20 this became the largest
 * remaining item, because a signature says a program came from the holder of a key and says
 * nothing about who asked for it to be armed, when, or on which binary.
 *
 * WHAT "WHO" CAN HONESTLY MEAN HERE, and it is less than it sounds. The loader speaks over an
 * AF_UNIX socket with no peer authentication, so there is no identity to record in the sense a
 * security reviewer means. What the KERNEL will vouch for is SO_PEERCRED: the pid, uid and gid
 * of the process on the other end, filled in by the kernel at connect() time and not settable
 * by the peer. That is attribution WITHIN a trust domain, not authentication ACROSS one --- in
 * this container everything runs as root, so uid=0 distinguishes nothing. It is still the
 * difference between "something armed rst_why" and "pid 1234, /usr/bin/python3, armed rst_why
 * at 15:04:07 on build 92454510", which is the difference between a log and an audit trail.
 *
 * WHY THE RECORD QUOTES THE REPLY VERBATIM. The verdict field is not computed a second time
 * from the operation's inputs --- it is the exact line the caller received. Deriving it
 * independently would create two answers to one question, and the failure mode of an audit
 * trail is not that it is missing but that it disagrees with what happened. Quoting removes
 * the possibility: if the caller was told OK, the record says OK, because they are the same
 * bytes.
 *
 * WHAT THIS DOES NOT GIVE, stated here rather than left to be discovered:
 *
 *   - NO TAMPER EVIDENCE IN THE FORMAT. A sequence number makes a DELETED record visible as a
 *     gap; it does nothing against a rewritten one. A hash chain would not help either, since
 *     anything able to rewrite the log can recompute the chain. Tamper evidence has to come
 *     from the SINK, which is why the primary sink is stderr: in this deployment that is the
 *     container's log stream, collected off-box by something TMM cannot write to. The optional
 *     file sink ($LS_AUDIT_PATH) is for tests and for hosts with no log collector, and is
 *     explicitly the weaker of the two.
 *   - NO RECORD OF WHAT THE PROGRAM DID. This is the control plane: loads, arms, mode changes.
 *     A program's own output is the tracepoint ring, and the two are deliberately separate ---
 *     an audit trail that could be flooded by data-path volume is not an audit trail.
 *   - NO CAUSAL LINK TO A HUMAN. peer_pid identifies a process, and in a Kubernetes exec that
 *     process is spawned by an API call this code cannot see. Closing that needs the request to
 *     carry an operator identity, which needs the wire format to grow a field and something to
 *     sign it.
 */
#ifndef LS_AUDIT_H
#define LS_AUDIT_H

#include <stddef.h>

struct shield_msg;

/* Once, from the loader thread before it accepts anything. Reads this binary's GNU build ID
 * out of /proc/self/exe and opens the optional file sink. Safe to call twice. */
void ls_audit_init(void);

/* One record. `fd` is the accepted connection --- peer credentials are read from it, so this
 * must be called before the socket is closed. `m` may be NULL when the message was too short
 * to interpret, which is itself worth recording: a record saying a peer connected and sent
 * garbage is evidence, and dropping it would make malformed traffic the one thing that leaves
 * no trace. `reply_text` is the line the caller received, verbatim. */
void ls_audit_op(int fd, const struct shield_msg *m, const char *reply_text);

/* Records emitted since init, for tests and for a "did anything get lost" check. */
unsigned long long ls_audit_count(void);

/* This binary's GNU build ID as hex, or "unknown". Exposed because the arming gate compares
 * build IDs and a reader needs to see the same string in both places. */
const char *ls_audit_build_id(void);

#endif /* LS_AUDIT_H */
