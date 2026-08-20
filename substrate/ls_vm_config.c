/*
 * ls_vm_config.c --- read the knobs once, at init.
 *
 * Deliberately dull. Every value is read from the environment exactly once, off
 * the data path, with a default that matches the shipped behaviour --- so an
 * unset environment behaves identically to the version before this file existed.
 * An unrecognised value falls back to the default rather than failing: a typo in
 * a pod spec should not stop TMM starting.
 */

#include "ls_vm_config.h"

#include <stdlib.h>
#include <string.h>

static bool
env_bool(const char *name, bool dflt)
{
    const char *v = getenv(name);
    if (v == NULL || *v == '\0')
        return dflt;
    if (!strcmp(v, "1") || !strcasecmp(v, "true") || !strcasecmp(v, "yes"))
        return true;
    if (!strcmp(v, "0") || !strcasecmp(v, "false") || !strcasecmp(v, "no"))
        return false;
    return dflt;
}

static uint32_t
env_u32(const char *name, uint32_t dflt)
{
    const char *v = getenv(name);
    if (v == NULL || *v == '\0')
        return dflt;
    char *end = NULL;
    unsigned long n = strtoul(v, &end, 10);
    if (end == v || *end != '\0' || n > 0xffffffffUL)
        return dflt;
    return (uint32_t)n;
}

static const char *
env_str(const char *name, const char *dflt)
{
    const char *v = getenv(name);
    return (v && *v) ? v : dflt;
}

/* disable=0, monitor=1, enforce=2 --- matching enum ls_mode. Accepts the words
 * because a pod spec is written by a person, not by the enum. */
static int
env_mode(const char *name, int dflt)
{
    const char *v = getenv(name);
    if (v == NULL || *v == '\0')
        return dflt;
    if (!strcasecmp(v, "disable") || !strcmp(v, "0")) return 0;
    if (!strcasecmp(v, "monitor") || !strcmp(v, "1")) return 1;
    if (!strcasecmp(v, "enforce") || !strcmp(v, "2")) return 2;
    return dflt;
}

void
ls_vm_config_load(struct ls_vm_config *c)
{
    if (c == NULL)
        return;
    memset(c, 0, sizeof *c);
    c->enable       = env_bool("LS_SHIELD_ENABLE", true);
    c->mode         = env_mode("LS_SHIELD_MODE", 2 /* enforce */);
    c->path         = env_str ("LS_SHIELD_PATH", NULL);
    c->section      = env_str ("LS_SHIELD_SECTION", NULL);
    c->function     = env_str ("LS_SHIELD_FUNCTION", NULL);
    c->fuel         = env_u32 ("LS_VM_FUEL", 0);
    c->jit          = env_bool("LS_VM_JIT", false);
    c->bench        = env_u32 ("LS_VM_BENCH", 0);
    c->timing       = env_bool("LS_VM_TIMING", false);
    c->report_every = env_u32 ("LS_VM_REPORT_EVERY", 0);
    c->samples      = env_bool("LS_VM_SAMPLES", false);
    c->selftest     = env_u32 ("LS_VM_SELFTEST", 0);
    c->verbose      = env_bool("LS_VM_VERBOSE", false);
    /*
     * SIGNATURE ENFORCEMENT, AND WHY THIS ONE IS NOT env_bool.
     *
     * A toggle on a security gate is the thing that ends up left off, so this one is
     * deliberately awkward in three ways that the other options are not:
     *
     *   1. It DEFAULTS ON. Absent, empty, misspelled, or set to anything this does not
     *      recognise all mean ENFORCE. env_bool would treat a typo as false for some inputs;
     *      here every value that is not the exact opt-out string enforces. A fat-fingered pod
     *      spec must not disable verification.
     *   2. The opt-out is a WORD, not "0" or "false". "LS_SIG_ENFORCE=i-am-debugging" cannot be
     *      arrived at by accident and cannot be mistaken for a tidy production setting when
     *      someone reads the manifest six months from now.
     *   3. It is read at STARTUP ONLY, never over the loader socket. An op that disables
     *      verification would hand the gate's own key to anyone who can reach the socket ---
     *      which is precisely the population the gate exists to constrain.
     *
     * ls_vm_load.c shouts on every load when this is off, for the same reason the pre-signature
     * loader shouted `unverified=yes`: a debugging session must not quietly become a demo.
     */
    {
        const char *v = getenv("LS_SIG_ENFORCE");
        c->sig_enforce = !(v != NULL && !strcmp(v, "i-am-debugging"));
    }
}
