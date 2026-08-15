/* dev_probe --- the DEVELOPER use case, in nine lines.
 *
 * Always falls through, so arming it CANNOT change traffic. Its entire output is
 * the host's own `fired` counter, which answers the question that stalls
 * debugging more often than any other: DOES THIS CODE PATH ACTUALLY EXECUTE, and
 * how often, on this box, with this config, under this traffic?
 *
 * That question is normally answered by adding a log line and rebuilding --- on a
 * data plane that means a build, a package, a rollout, and a restart, and the
 * answer arrives long after the question. This is armed at a function entry on a
 * TMM that is already running and disarmed again the same way.
 *
 * It is deliberately the OPPOSITE of a tracepoint: no chosen structure, no
 * schema, no egress. A tracepoint is placed once and exposes something decided
 * in advance; this goes anywhere, answers one question, and is removed. Both use
 * the same VM, loader and verifier; only the attach and the intent differ.
 */
#include "ls_tp_http_bpf.h"

__attribute__((section("fentry/dev_probe"), used))
unsigned long long
shield(struct ls_tp_http_hdrs *c)
{
    (void)c;                       /* the ctx is whatever this function's args are */
    return LS_FALLTHROUGH;         /* never alters traffic --- counting only */
}
