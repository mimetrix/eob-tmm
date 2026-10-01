/* Completion-only context. No application pointer is writable through it. */
#ifndef LS_SNAPSHOT_H
#define LS_SNAPSHOT_H

#define LS_SNAPSHOT_SECTION "fexit/snapshot/"
#define LS_SNAPSHOT_PREFIX_LEN 15u
#define LS_SNAPSHOT_ENTRY 1u
#define LS_SNAPSHOT_RETURN 2u
#define LS_SNAPSHOT_CAPTURED 1u

struct ls_snapshot_ctx {
    __UINT64_TYPE__ arg[5];
    __UINT64_TYPE__ no_return;
    __UINT32_TYPE__ phase;
    __UINT32_TYPE__ flags;
    __UINT64_TYPE__ sequence;
    __UINT64_TYPE__ state[4];
};
_Static_assert(sizeof(struct ls_snapshot_ctx) == 96, "snapshot context size");
_Static_assert(__builtin_offsetof(struct ls_snapshot_ctx, state) == 64,
               "snapshot state offset");

/* Host-only identity. Bytecode cannot change it through its private context. */
struct ls_snapshot_id {
    __UINT64_TYPE__ instance;
    __UINT64_TYPE__ epoch;
};
#endif
