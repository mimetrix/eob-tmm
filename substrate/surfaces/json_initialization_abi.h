#ifndef JSON_INITIALIZATION_ABI_H
#define JSON_INITIALIZATION_ABI_H
#include "../ls_snapshot.h"
#define JI_MAGIC 0x4a494e49u
/* Status: 0 unknown, 1 initialized, 2 disabled, 3 other event,
 * 4 read failed, 5 unsupported context, 6 configuration changed. */
struct ji_event {
    __UINT32_TYPE__ magic, abi;
    __UINT64_TYPE__ instance, revision, run, invocation, monotonic_ns;
    __UINT64_TYPE__ sequence, output_failures;
    __UINT32_TYPE__ code, status, flags, flow_side;
    __UINT32_TYPE__ reads, source_bytes, guards, reserved;
};
_Static_assert(sizeof(struct ji_event) == 96, "initialization event size");
struct ji_capture {
    __UINT64_TYPE__ instance, revision, run;
    __UINT32_TYPE__ evidence, counts;
};
_Static_assert(sizeof(struct ji_capture) == 32, "frame state size");
#endif
