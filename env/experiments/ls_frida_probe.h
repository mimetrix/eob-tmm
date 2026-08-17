/* ls_frida_probe.h --- prototypes for the frida-gum experiment.
 *
 * Exists only because TMM builds with -Werror=missing-prototypes, which is the right
 * setting: a non-static function with no prototype is one whose callers cannot be
 * type-checked against it. No TMM or frida type appears here, so ls_vm.c can call the
 * probe without either include world reaching it.
 */
#ifndef LS_FRIDA_PROBE_H
#define LS_FRIDA_PROBE_H

/* Off unless LS_FRIDA_TARGET names an address. Called once from ls_vm.c's init. */
void ls_frida_probe_init(void);

/* Hits since attach, or 0 when the probe never armed. */
unsigned long long ls_frida_hits(void);

#endif /* LS_FRIDA_PROBE_H */
