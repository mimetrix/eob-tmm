/* Runs the verified shield through ls_vm.c's real code path. Not TMM --- a host
 * with the same compiler, the same libubpf.a, the same ls_vm.c and the same
 * verified object. Proves the bytecode EXECUTES and returns the right verdict. */
#include <stdio.h>
#include <string.h>
#include "ls_vm.h"
#include "ls_ctx_http_psm.h"
#include "ls_shield_blob.h"

static int fails;
static void check(const char *what, int got, int want)
{
    printf("  %-46s got=%d want=%d  %s\n", what, got, want,
           got == want ? "ok" : "FAIL");
    if (got != want) fails++;
}

int main(void)
{
    printf("shield object: %zu bytes, section %s\n\n",
           sizeof ls_shield_blob, LS_SHIELD_SECTION);

    if (!ls_vm_init()) { puts("ls_vm_init failed"); return 1; }

    int slot = ls_vm_arm(ls_shield_blob, sizeof ls_shield_blob,
                         LS_SHIELD_SECTION, LS_SHIELD_FUNCTION, LS_MODE_ENFORCE);
    printf("ls_vm_arm -> slot %d\n", slot);
    if (slot < 0) { puts("arm failed --- no bytecode will run"); return 1; }

    char name[] = "protocol-transfer-log-profile";

    /* the CVE condition: no profile configured, so the pointer is NULL */
    struct ls_ctx_http_psm null_ptlp = { 0 };
    check("ptlp==NULL -> SAFE_RETURN (the CVE case)",
          ls_vm_call(slot, &null_ptlp, sizeof null_ptlp), LS_SAFE_RETURN);

    /* profile present but its name is NULL --- the second guard */
    struct ls_ctx_http_psm no_name = { .ptlp = 0x1000, .ptlp_name = 0, .name_len = 0 };
    check("ptlp!=NULL, name==NULL -> SAFE_RETURN",
          ls_vm_call(slot, &no_name, sizeof no_name), LS_SAFE_RETURN);

    /* zero length --- the third guard */
    struct ls_ctx_http_psm empty = { .ptlp = 0x1000,
                                     .ptlp_name = (unsigned long long)(size_t)name,
                                     .name_len = 0 };
    check("name_len==0 -> SAFE_RETURN",
          ls_vm_call(slot, &empty, sizeof empty), LS_SAFE_RETURN);

    /* the healthy path: everything present, so TMM must run its own body */
    struct ls_ctx_http_psm good = { .ptlp = 0x1000,
                                    .ptlp_name = (unsigned long long)(size_t)name,
                                    .name_len = (unsigned)strlen(name) };
    check("all present -> FALLTHROUGH (original body runs)",
          ls_vm_call(slot, &good, sizeof good), LS_FALLTHROUGH);

    /* monitor mode must COUNT the hit and apply nothing */
    int mslot = ls_vm_arm(ls_shield_blob, sizeof ls_shield_blob,
                          LS_SHIELD_SECTION, LS_SHIELD_FUNCTION, LS_MODE_MONITOR);
    check("monitor mode: CVE case -> FALLTHROUGH (counted, not applied)",
          ls_vm_call(mslot, &null_ptlp, sizeof null_ptlp), LS_FALLTHROUGH);

    /* an unarmed slot must never enforce */
    check("unarmed slot -> FALLTHROUGH",
          ls_vm_call(7, &null_ptlp, sizeof null_ptlp), LS_FALLTHROUGH);
    check("out-of-range slot -> FALLTHROUGH",
          ls_vm_call(99, &null_ptlp, sizeof null_ptlp), LS_FALLTHROUGH);

    /* O14: the identity check must REFUSE a mismatch, not just accept a match. */
    puts("");
    check("wrong section for this symbol -> refuse",
          ls_vm_arm(ls_shield_blob, sizeof ls_shield_blob,
                    "fentry/some_other_hook", LS_SHIELD_FUNCTION, LS_MODE_ENFORCE), -1);
    check("symbol not in the object -> refuse",
          ls_vm_arm(ls_shield_blob, sizeof ls_shield_blob,
                    LS_SHIELD_SECTION, "not_a_function", LS_MODE_ENFORCE), -1);
    check("truncated object -> refuse",
          ls_vm_arm(ls_shield_blob, 64, LS_SHIELD_SECTION, LS_SHIELD_FUNCTION,
                    LS_MODE_ENFORCE), -1);

    ls_vm_fini();
    printf("\n%s\n", fails ? "FAILURES" : "all checks passed --- bytecode executed");
    return fails ? 1 : 0;
}
