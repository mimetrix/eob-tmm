#ifndef LS_ACTIVITY_GROUP_ABI_H
#define LS_ACTIVITY_GROUP_ABI_H
#include "token_method_abi.h"
#define AG_MAGIC 0x41474331u
struct ag_frame {
    jm_u32 magic, abi, length, side;
    jm_u64 owner, exchange;
    jm_u32 status, phase;
    jm_u64 invocation;
    unsigned char payload[144];
};
_Static_assert(sizeof(struct ag_frame) == 192, "activity frame size");
#endif
