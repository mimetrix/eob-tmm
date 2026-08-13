/* check_integrated.c --- the vertical slice, joined for the first time.
 *
 * Every prior harness proved ONE seam:
 *   check_tramp        real trampoline + dispatch, but the hook is baked into victim.S
 *   check_arm          real arming, but onto the test_tramp STUB, on a MAP_SHARED page
 *   check_swap_realtext real arming + safe swap on real private .text, but no VM
 *
 * This joins them: the REAL trampoline (trampoline_x86_64.S) -> the REAL dispatch
 * (ls_tramp.c) -> the REAL VM (ls_vm.c, running verified bytecode) -> armed onto a
 * REAL private-.text function through /proc/self/mem (ls_arm.c). The VM's verdict,
 * not a stub's g_verdict, drives whether the hooked body runs.
 *
 * Four phases:
 *   A  unarmed           -> body runs, returns 0xBEEF
 *   B  armed, PASS shield -> VM returns FALLTHROUGH -> body still runs
 *   C  armed, BLOCK shield-> VM returns SAFE_RETURN -> body SKIPPED, caller sees safe value
 *   D  disarmed          -> body runs again
 *
 * Build (on the x86-64 box, against the bumped ubpf):
 *   gcc -O2 -fcf-protection=full -fpatchable-function-entry=5,0 -pthread \
 *       -I. -I~/ubpf-new/vm/inc -I~/ubpf-new/build/vm \
 *       check_integrated.c ls_vm.c ls_vm_config.c ls_tramp.c ls_arm.c \
 *       trampoline_x86_64.S ~/ubpf-new/build/lib/libubpf.a -o check_integrated
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "ls_vm.h"

extern void ls_trampoline_entry(void);
extern unsigned char ls_tramp_slot_insn[];   /* the `movl $imm32,%edi`; +1 is the imm */
int ls_arm(void *fn, void *trampoline);
int ls_disarm(void *fn);

/* A real out-of-line function carrying the -fpatchable pad. Called through a
 * volatile pointer so the compiler cannot fold or inline it away. */
static volatile uint64_t g_body_ran;
__attribute__((noinline, used))
uint64_t victim(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    (void)a; (void)b; (void)c; (void)d; (void)e;
    g_body_ran++;
    return 0xBEEF;
}
typedef uint64_t (*victim_fn)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static victim_fn call_victim = victim;

/* Set the trampoline's per-hook slot immediate. In the product this is baked when
 * the (one-per-hook) trampoline is created; here we patch the shared stub's imm32
 * through /proc/self/mem, the same path arming uses. */
static int patch_slot(int slot)
{
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) { perror("open"); return -1; }
    int32_t s = slot;
    ssize_t w = pwrite(fd, &s, 4, (off_t)(uintptr_t)(ls_tramp_slot_insn + 1));
    close(fd);
    __builtin___clear_cache((char*)ls_tramp_slot_insn, (char*)ls_tramp_slot_insn + 8);
    return w == 4 ? 0 : -1;
}

static void *slurp(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb"); if (!f) { perror(p); return NULL; }
    fseek(f, 0, SEEK_END); *n = ftell(f); fseek(f, 0, SEEK_SET);
    void *b = malloc(*n);
    if (!b || fread(b, 1, *n, f) != *n) { fclose(f); return NULL; }
    fclose(f); return b;
}

static void show(int slot, const char *tag)
{
    struct ls_stats st;
    if (ls_vm_stats(slot, &st))
        printf("        slot %d [%s]: armed=%d mode=%d fired=%llu safe_returns=%llu errors=%llu\n",
               slot, tag, st.armed, st.mode,
               (unsigned long long)st.fired, (unsigned long long)st.safe_returns,
               (unsigned long long)st.errors);
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s demo_pass.o demo_block.o\n", argv[0]); return 2; }
    int fails = 0;
    size_t np, nb;
    void *pass = slurp(argv[1], &np), *block = slurp(argv[2], &nb);
    if (!pass || !block) return 2;

    if (!ls_vm_init()) { puts("FAIL ls_vm_init"); return 1; }

    int sp = ls_vm_arm(pass,  np, "fentry/demo_pass",  "shield", LS_MODE_ENFORCE);
    int sb = ls_vm_arm(block, nb, "fentry/demo_block", "shield", LS_MODE_ENFORCE);
    if (sp < 0 || sb < 0) { printf("FAIL load (pass=%d block=%d)\n", sp, sb); return 1; }
    printf("  loaded shields: PASS->slot %d, BLOCK->slot %d\n", sp, sb);

    /* A --- unarmed */
    g_body_ran = 0;
    uint64_t r = call_victim(1,2,3,4,5);
    printf("  A unarmed:      ret=%#llx body_ran=%llu\n", (unsigned long long)r, (unsigned long long)g_body_ran);
    if (r != 0xBEEF || g_body_ran != 1) { puts("  FAIL A"); fails++; } else puts("  ok A  body ran, no hook");

    /* B --- armed with PASS (FALLTHROUGH): body should still run */
    if (patch_slot(sp) != 0) { puts("FAIL patch_slot"); return 1; }
    if (ls_arm((void*)victim, (void*)ls_trampoline_entry) != 0) { puts("  FAIL arm (rel32? pad?)"); return 1; }
    g_body_ran = 0;
    r = call_victim(0xA1,0xB2,0xC3,0xD4,0xE5);
    printf("  B armed/PASS:   ret=%#llx body_ran=%llu\n", (unsigned long long)r, (unsigned long long)g_body_ran);
    if (r != 0xBEEF || g_body_ran != 1) { puts("  FAIL B (VM should fall through)"); fails++; } else puts("  ok B  VM said FALLTHROUGH, body ran");
    show(sp, "PASS");

    /* C --- swap the live slot to BLOCK (SAFE_RETURN): body should be skipped */
    if (patch_slot(sb) != 0) { puts("FAIL patch_slot"); return 1; }
    g_body_ran = 0;
    r = call_victim(9,9,9,9,9);
    printf("  C armed/BLOCK:  ret=%#llx body_ran=%llu\n", (unsigned long long)r, (unsigned long long)g_body_ran);
    if (g_body_ran != 0) { puts("  FAIL C (body ran despite SAFE_RETURN)"); fails++; } else puts("  ok C  VM said SAFE_RETURN, body SKIPPED");
    if (r != 0) { puts("  FAIL C safe value"); fails++; } else puts("  ok C  safe value delivered to caller");
    show(sb, "BLOCK");

    /* D --- disarm: back to baseline */
    if (ls_disarm((void*)victim) != 0) { puts("  FAIL disarm"); fails++; }
    g_body_ran = 0;
    r = call_victim(1,2,3,4,5);
    printf("  D disarmed:     ret=%#llx body_ran=%llu\n", (unsigned long long)r, (unsigned long long)g_body_ran);
    if (r != 0xBEEF || g_body_ran != 1) { puts("  FAIL D"); fails++; } else puts("  ok D  back to baseline");

    printf("\n  %s\n", fails ? "FAILURES" :
        "INTEGRATED: real trampoline + real VM + arming/swap on real .text, end to end");
    ls_vm_fini();
    return fails;
}
