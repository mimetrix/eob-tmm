#ifndef CHECK_SNAPSHOT_ABI_H
#define CHECK_SNAPSHOT_ABI_H
#include "ls_snapshot.h"
struct snapshot_observation {
    __UINT64_TYPE__ sequence, serial, owner, no_return, node, event;
    __UINT64_TYPE__ phase, flags, known, eligible, marker;
};
#endif
