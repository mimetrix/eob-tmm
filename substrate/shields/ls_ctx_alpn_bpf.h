/* The ALPN validation ctx --- flat, bounded, no pointers.
 *
 * alpn_ext and alpn_ext_sz are derived from `sc` inside ssl_alpn_match, not
 * passed as arguments, so the host lifts them into this struct before the
 * program runs. The extension is COPIED, bounded at LS_ALPN_MAX: a program
 * cannot chase a pointer, and an unbounded copy would just move the overread
 * into the builder.
 *
 * LS_ALPN_MAX is a power of two so an index can be masked into range with a
 * single AND, which is what lets PREVAIL prove every access is in bounds
 * without reasoning about the attacker-supplied length at all.
 *
 * WHY 64 AND NOT MORE. PREVAIL's `tracing` program type --- what the `fentry/`
 * section prefix selects --- describes a 96-BYTE ctx. A larger struct is not
 * merely discouraged, it is unreadable: an access past 96 fails verification
 * with "Upper bound must be at most 96". A first version used 256 bytes of ALPN
 * and was rejected outright.
 *
 * So 4 + 4 + 64 = 72 bytes, inside the cap. This is a real ceiling on the whole
 * shield idea and worth stating plainly: a program can inspect at most ~88 bytes
 * of attacker-controlled input directly. Anything larger has to be reduced by
 * the host into a verdict or a summary before the program sees it.
 *
 * 64 bytes is ample for genuine ALPN --- "h2" plus "http/1.1" is 14 bytes with
 * length prefixes. A longer list sets `truncated`, and the program refuses it
 * rather than guessing, which is the safe direction.
 */
#ifndef LS_CTX_ALPN_BPF_H
#define LS_CTX_ALPN_BPF_H

#define LS_ALPN_MAX       64u          /* power of two, and see the 96-byte cap */
#define LS_ALPN_ENTRIES   64u          /* CONSTANT trip count, not alpn_sz    */

struct ls_ctx_alpn {
    unsigned int  alpn_sz;             /* extension size as TMM computed it   */
    unsigned int  truncated;           /* 1 if the real extension exceeded MAX */
    unsigned char alpn[LS_ALPN_MAX];
};

_Static_assert(sizeof(struct ls_ctx_alpn) == 72,
               "ALPN ctx must be 72 bytes --- host and program disagree");
_Static_assert(sizeof(struct ls_ctx_alpn) <= 96,
               "PREVAIL's fentry ctx is 96 bytes; a larger struct cannot be read");
_Static_assert((LS_ALPN_MAX & (LS_ALPN_MAX - 1)) == 0,
               "LS_ALPN_MAX must be a power of two for the index mask");

#define LS_FALLTHROUGH 0u
#define LS_SAFE_RETURN 1u

#endif
