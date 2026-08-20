/* ls_sig.h --- refuse any program not signed by the holder of the private key.
 *
 * THE GAP THIS CLOSES is the largest one on GROUND_TRUTH.md: the loader accepts whatever
 * arrives on the socket and prints `unverified=yes` on every load. Everything else in this
 * substrate --- PREVAIL, the identity gates, the build-id refusal --- constrains what a program
 * may DO. None of it constrains WHO may send one. That is what makes the current state lab-only,
 * and no measurement changes it.
 *
 * WHAT IS SIGNED, and this deviates from shield_abi.h's comment on purpose.
 *
 * The comment there says the signature covers "op, epoch, mode, prog_len, binding, prog". This
 * signs the 112-byte `struct shield_binding` ONLY, and relies on the binding to commit to the
 * program body through its prog_sha256 field. Two reasons, both recorded in
 * 02-RESEARCH-PARAMETERS.md P6 so the choice can be argued with:
 *
 *   - `epoch` is reused by the current loader to carry the SLOT NUMBER. Signing it would tie a
 *     signed program to one slot, which buys nothing --- the slot is not a security boundary ---
 *     and would force re-signing to move a program between slots.
 *   - `mode` is already bounded by the signed `mode_ceiling` inside the binding. That field
 *     exists for exactly this, and bounding is stronger than fixing: one signature can permit
 *     MONITOR and refuse ENFORCE.
 *
 * So the signed statement is: "this key asserts that the program with THIS hash may be armed at
 * THIS hook, on builds in THIS range, at no more than THIS mode, until THIS expiry." Everything
 * a caller could otherwise lie about is inside it.
 *
 * WHY Ed25519 AND WHY TMM'S OWN OpenSSL. TMM already links OpenSSL 3.1.4 and its own source
 * calls EVP in three files, with headers at /usr/tmm/include reached by an include path the
 * build already passes. So no crypto is vendored and no new dependency is introduced --- which
 * matters more here than elsewhere, because vendored crypto in a security gate is the first
 * thing a review will object to. Ed25519 because the key is 32 bytes, the signature is 64
 * (SHIELD_SIG_MAX is already 64), and there are no parameters to choose wrongly.
 *
 * WHERE IT RUNS. On the handoff thread, with the rest of the load work --- EVP allocates, and
 * TMM's allocator freezes on the loader thread. That is not a detail: it is why this lives
 * behind ls_prep rather than at the socket.
 *
 * FAIL CLOSED. Every path that is not an explicit verification success refuses. A missing key, a
 * malformed signature, an EVP failure and a hash mismatch are all the same answer.
 */
#ifndef LS_SIG_H
#define LS_SIG_H

#include <stddef.h>
#include <stdint.h>

/* Distinct causes, because "refused" without a reason sends the reader to the wrong place. They
 * are returned to the loader and logged; they are NOT sent to a remote caller in a form that
 * would let it probe the difference between a bad key and a bad hash. */
enum ls_sig_result {
    LS_SIG_OK = 0,
    LS_SIG_NO_PUBKEY,        /* no key was baked in --- refuse rather than accept all   */
    LS_SIG_BAD_ARGS,
    LS_SIG_EVP_FAILED,       /* OpenSSL could not even attempt it                       */
    LS_SIG_BAD_SIGNATURE,    /* the signature is INVALID --- EVP returned 0             */
    LS_SIG_EVP_ERROR,        /* EVP returned NEGATIVE: a fault, not a verdict. Conflating
                              * this with an invalid signature sends the reader to look for
                              * a forgery when the actual problem is the crypto library ---
                              * which is exactly what happened on 2026-08-20. */
    LS_SIG_BODY_MISMATCH     /* signature good, but prog_sha256 does not match the body */
};

const char *ls_sig_strerror(enum ls_sig_result r);

/*
 * Verify a load request.
 *
 *   binding      the 112 bytes exactly as they arrived on the wire
 *   binding_len  must equal sizeof(struct shield_binding); a short read is refused rather
 *                than zero-padded, because a caller controls this length
 *   sig          64 bytes
 *   prog         the bytecode body, checked against binding->prog_sha256
 *
 * Returns LS_SIG_OK only when the signature verifies AND the body hashes to what the binding
 * says. Any other value means do not load.
 */
enum ls_sig_result ls_sig_verify(const void *binding, size_t binding_len,
                                 const uint8_t *sig, size_t sig_len,
                                 const void *prog, size_t prog_len);

/* Whether a key is present at all. Reported at startup so an operator learns that this build
 * cannot verify anything BEFORE trying to load, rather than from a refusal. */
int ls_sig_have_pubkey(void);

#endif /* LS_SIG_H */
