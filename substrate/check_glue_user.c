/* check_glue_user.c --- a NON-owning includer of ls_map_glue.h.
 *
 * Its whole job is to exist. While the glue's state was `static` in the header,
 * this TU would have compiled and linked cleanly with its OWN private copy of
 * g_ls_shapes --- so relocation's work would have been invisible to any helper
 * compiled here, and nothing at build or run time would have said so. Now the
 * state is extern, and check_glue_owner.c proves both files see one array.
 */
#include <stdint.h>
#include "ls_map_glue.h"

unsigned
user_nshapes(void)
{
    return (unsigned)atomic_load_explicit(&g_ls_nshapes, memory_order_acquire);
}

int
user_install(void *vm)
{
    return ls_map_glue_install((struct ubpf_vm *)vm);
}
