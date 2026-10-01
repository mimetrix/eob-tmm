/* Ordinary-hook tests have no production VM. Their slots are never snapshots. */
#ifndef CHECK_SNAPSHOT_STUBS_H
#define CHECK_SNAPSHOT_STUBS_H
#include "ls_vm.h"
#include "ls_program.h"
#include <assert.h>
int ls_program_dispatch(unsigned site, uint64_t ip,
                        const struct ls_ctx_generic *ctx, struct ls_tramp_result *out)
{
    (void)site; (void)ip; (void)ctx; (void)out;
    return 0;
}
int ls_vm_snapshot_identity(int slot, struct ls_snapshot_id *identity)
{
    (void)slot;
    *identity = (struct ls_snapshot_id){0};
    return 0;
}
int ls_vm_snapshot_call(int slot, const struct ls_snapshot_id *identity,
                        struct ls_snapshot_ctx *ctx)
{
    (void)slot; (void)identity; (void)ctx;
    assert(!"ordinary hook entered snapshot path");
    return -1;
}
#endif
