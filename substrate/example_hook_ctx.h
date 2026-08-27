/*
 * example_hook_ctx.h — the ctx one hook exposes, as a concrete example.
 *
 * hook-point-map.json declares, for the hook `ls_request_eval_decision`, the
 * field offsets of its argument struct. check_offsets.py compiles those declared
 * offsets against THIS header and fails on any mismatch — which is the check a
 * real hook-map generator must have, and which caught a live wrong-offset bug in
 * this repo (see the note at the top of check_offsets.py).
 *
 * SCOPE: this is an EXAMPLE ctx for exercising the offset check, not a TMM
 * structure and not a proposed ABI. In product the ctx layout comes from the
 * build's own debug info, and the map records its provenance; nothing here is
 * hand-maintained. The struct is deliberately small and dull: two 16-bit fields,
 * two 32-bit fields and a byte array, chosen because that mix is enough to expose
 * padding and alignment mistakes in a generator.
 */
#ifndef EXAMPLE_HOOK_CTX_H
#define EXAMPLE_HOOK_CTX_H

#include <stdint.h>

struct ls_ctx {
    uint16_t opcode;          /* offset  0 — the field a predicate branches on   */
    uint16_t payload_len;     /* offset  2 — declared length from the header     */
    uint32_t avail_len;       /* offset  4 — bytes actually buffered             */
    uint32_t mode;            /* offset  8 — host-supplied; the field whose      */
                              /*             omission from the map was the bug   */
                              /*             check_offsets.py was written for    */
    uint8_t  head[16];        /* offset 12 — leading payload bytes               */
};                            /* sizeof == 28                                    */

#endif /* EXAMPLE_HOOK_CTX_H */
