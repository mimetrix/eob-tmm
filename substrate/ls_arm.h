/* ls_arm.h --- patched-entry hooking: arm/disarm a LIVE function.
 *
 * Live-SURFACE mechanics. `ls_` is the live surface embedded in the data
 * plane; these primitives are used by ANY consumer of it (CVE shielding is
 * consumer #1, with observability, steering and self-tuning as peers), which
 * is why this header is not named for the shield.
 *
 * The point of this mechanism is that arming happens while TMM is RUNNING and
 * traffic is flowing --- no rebuild, no restart. That is what makes a shield
 * "live". Arming at startup would need a restart and would defeat the purpose,
 * so the write goes through ls_swap_write5(), the kernel-proven text_poke_bp
 * protocol, which is safe against other cores executing the same bytes.
 */
#ifndef LS_ARM_H
#define LS_ARM_H
#include <stdint.h>

struct ls_tramp_result { int verdict; uint64_t safe_value; };
struct ls_tramp_result ls_tramp_dispatch(int slot, uint64_t a0, uint64_t a1,
                                         uint64_t a2, uint64_t a3, uint64_t a4);

/* single-writer forms (no concurrent executor; used only off the live path) */
int ls_arm(void *fn, void *trampoline);
int ls_disarm(void *fn);

/* LIVE forms --- safe while other cores are executing the target */
int ls_arm_live(void *fn, void *trampoline, int slot);
int ls_disarm_live(void *fn);

/* the safe swap: rewrite 5 bytes of executed code under contention */
int  ls_swap_write5(uint8_t *pad, const uint8_t bytes[5]);
void ls_swap_trap_install(void);
#endif
