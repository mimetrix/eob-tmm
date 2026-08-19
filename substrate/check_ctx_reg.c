/* check_ctx_reg.c --- the registration set links, is complete, and resolves exactly.
 *
 * WHAT THIS IS GUARDING. The builder for a hook is now found by looking its NAME up in a
 * linker set that each builder contributes to (ls_ctx_reg.h). That removes the hand-written
 * table, and it introduces one new failure mode: if the linker discards the ls_ctx_regs
 * section, every lookup returns NULL and every typed hook silently degrades to the generic
 * five-register context. Nothing crashes. Programs still run. The reset feed and the TLS feed
 * just stop producing records, and the reason is invisible.
 *
 * Silent-and-safe is the combination this repository keeps losing days to, so:
 *
 *   1. the set is non-empty                       --- the section survived the link
 *   2. the linked count equals the number of LS_CTX_REGISTER uses in the sources
 *                                                 --- nothing was dropped, nothing forgotten
 *   3. every registration has a hook, a builder, and a size within the ctx ceiling
 *   4. lookup is EXACT --- "rst_why" must not match "rst_why_preserve"
 *   5. an unregistered name resolves to NULL, not to something plausible
 *   6. no two registrations claim the same hook
 *
 * (2) is the one that matters most, and it is why this file counts the macro uses by reading
 * the sources rather than hardcoding a number: a hardcoded expected count is a hand-written
 * table again, one integer wide.
 */
#include "ls_ctx_reg.h"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>

/* Count LS_CTX_REGISTER( uses across the substrate .c files, skipping the definition in the header
 * and this file. The sources are the authority on how many builders exist; the linker output
 * is the claim being checked against them. */
static int
count_registrations_in_sources(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int total = 0;

    if (d == 0) {
        fprintf(stderr, "*** cannot open %s --- run this from the substrate directory\n", dir);
        return -1;
    }
    while ((e = readdir(d)) != 0) {
        char path[512];
        char line[1024];
        FILE *f;
        size_t n = strlen(e->d_name);

        if (n < 3 || strcmp(e->d_name + n - 2, ".c") != 0)
            continue;
        if (strcmp(e->d_name, "check_ctx_reg.c") == 0)
            continue;
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        f = fopen(path, "r");
        if (f == 0)
            continue;
        while (fgets(line, sizeof line, f) != 0) {
            /* A use, not the definition: the definition is in the header and is a #define. */
            const char *p = strstr(line, "LS_CTX_REGISTER(");
            if (p == 0)
                continue;
            if (strstr(line, "#define") != 0)
                continue;
            total++;
        }
        fclose(f);
    }
    closedir(d);
    return total;
}

int
main(int argc, char **argv)
{
    const char *dir = (argc > 1) ? argv[1] : ".";
    unsigned n = ls_ctx_reg_count();
    const struct ls_ctx_reg *const *p;
    int in_sources;
    int checks = 0;

    /* 1. the section survived the link */
    assert(n > 0);
    checks++;
    printf("  ok    %u builder(s) linked --- the ls_ctx_regs section survived\n", n);

    /* 2. the count matches the sources */
    in_sources = count_registrations_in_sources(dir);
    if (in_sources < 0)
        return 1;
    if ((unsigned)in_sources != n) {
        fprintf(stderr, "*** %d LS_CTX_REGISTER use(s) in %s/*.c but %u linked.\n"
                        "    A builder was added without being linked in, or the linker is\n"
                        "    dropping part of the section. Either way some hook is silently\n"
                        "    getting the generic ctx.\n", in_sources, dir, n);
        return 1;
    }
    checks++;
    printf("  ok    linked count matches %d LS_CTX_REGISTER use(s) in the sources\n", in_sources);

    /* 3. every entry is usable, and 6. no duplicate hooks */
    for (p = __start_ls_ctx_regs; p < __stop_ls_ctx_regs; p++) {
        const struct ls_ctx_reg *const *q;

        assert((*p)->hook != 0 && (*p)->hook[0] != '\0');
        assert((*p)->build != 0);
        assert((*p)->size > 0 && (*p)->size <= LS_CTX_OUT_MAX);
        checks++;
        for (q = p + 1; q < __stop_ls_ctx_regs; q++) {
            if (strcmp((*p)->hook, (*q)->hook) == 0) {
                fprintf(stderr, "*** two registrations claim hook '%s'. Lookup would return\n"
                                "    whichever the linker happened to place first.\n",
                        (*p)->hook);
                return 1;
            }
        }
        /* And it must be findable by its own name --- a registration the lookup cannot
         * reach is worse than no registration, because the hook looks supported. */
        assert(ls_ctx_reg_lookup((*p)->hook) == *p);
        checks++;
    }
    printf("  ok    every entry has a hook, a builder, a size <= %u, and is findable\n",
           LS_CTX_OUT_MAX);
    printf("  ok    no two registrations claim the same hook\n");

    /* 4. EXACT match. This is the assertion that keeps a prefix optimisation from ever
     * handing rst_why_preserve's registers to rst_why's builder --- the preserve form has no
     * `reason`, so its cause is in a4, and reading a5 dereferences whatever the caller left
     * in r9 as a string. */
    {
        const struct ls_ctx_reg *a = ls_ctx_reg_lookup("rst_why");
        const struct ls_ctx_reg *b = ls_ctx_reg_lookup("rst_why_preserve");

        if (a != 0 && b != 0) {
            assert(a != b);
            assert(a->build != b->build);
            assert(a->hook_id != b->hook_id);
            checks += 3;
            printf("  ok    rst_why and rst_why_preserve resolve to DIFFERENT builders\n");
        }
        /* A name that is a strict prefix of a registered one must not match it. */
        assert(ls_ctx_reg_lookup("rst_wh") == 0);
        assert(ls_ctx_reg_lookup("rst_why_") == 0);
        checks += 2;
        printf("  ok    a prefix of a registered hook does not match it\n");
    }

    /* 5. the common case: an ordinary function nobody wrote a builder for */
    assert(ls_ctx_reg_lookup("mrhttp_proxy_route_message") == 0);
    assert(ls_ctx_reg_lookup("") == 0);
    assert(ls_ctx_reg_lookup(0) == 0);
    checks += 3;
    printf("  ok    an unregistered hook resolves to NULL --- generic ctx, no dereference\n");

    printf("  ok    check_ctx_reg: %d assertions\n", checks);
    return 0;
}
