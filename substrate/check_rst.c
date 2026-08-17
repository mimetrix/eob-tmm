/* The reset record: basename extraction, bounds, and the program's predicate.
 *
 * The builder runs on a TEARDOWN path, where state is already unusual --- which is
 * exactly where a tracepoint that faults does the most damage. So the guards get
 * asserted rather than assumed, and the boundary cases (path with no slash, path
 * ending in a slash, name longer than the budget) are the ones that would produce
 * plausible-looking wrong output rather than an obvious failure.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ls_ctx_rst.h"

#define FALLTHROUGH 0u
#define SAFE_RETURN 1u
static unsigned int shield(const struct ls_ctx_rst *c)
{ return c->err != LS_ERR_UNKNOWN ? SAFE_RETURN : FALLTHROUGH; }

int
main(void)
{
    struct ls_ctx_rst c;
    int n = 0;

    /* 92 after Phase 3 added cause[]. The ceiling assertion is the load-bearing
     * one: exceed 96 and PREVAIL rejects every program over this ctx with "Upper
     * bound must be at most 96", at verification time rather than here. */
    assert(sizeof(struct ls_ctx_rst) == 92);                                 n++;
    assert(sizeof(struct ls_ctx_rst) <= 96);   /* PREVAIL ctx ceiling */     n++;
    assert(LS_RST_FILE_MAX + LS_RST_CAUSE_MAX + 20u <= 96u);                 n++;

    /* 1. a real __FILE__ from this tree --- basename only, since the prefix is
     *    identical on every record and the budget is 48 bytes */
    ls_ctx_rst_build(&c, "./src/modules/hudfilter/http/http1x.c", 1766,
                     LS_ERR_UNKNOWN, 0, "HTTP header count exceeded by client");
    assert(strcmp(c.file, "http1x.c") == 0);                                 n++;
    assert(c.file_len == 8 && c.lineno == 1766);                             n++;
    assert(shield(&c) == FALLTHROUGH);   /* unattributed */                  n++;

    /* 2. an attributed teardown --- the counted class */
    ls_ctx_rst_build(&c, "./src/net/tcp4_proxy.c", 903, LS_ERR_EXPIRED, 0,
                     "Closing");
    assert(strcmp(c.file, "tcp4_proxy.c") == 0 && c.err == LS_ERR_EXPIRED);  n++;
    assert(shield(&c) == SAFE_RETURN);                                       n++;

    /* 3. no slash at all --- must keep the whole name, not drop it */
    ls_ctx_rst_build(&c, "ssl.c", 42, LS_ERR_REJECT, 7, "no cipher");
    assert(strcmp(c.file, "ssl.c") == 0 && c.reason == 7);                   n++;

    /* 4. trailing slash --- basename is empty, and that must not read past it */
    ls_ctx_rst_build(&c, "a/b/", 1, LS_ERR_UNKNOWN, 0, "x");
    assert(c.file_len == 0 && c.file[0] == '\0');                            n++;

    /* 5. longer than the budget: truncated, NUL-terminated, never overrun */
    {
        char big[200];
        memset(big, 'x', sizeof big); big[sizeof big - 1] = '\0'; big[0] = '/';
        ls_ctx_rst_build(&c, big, 9, LS_ERR_UNKNOWN, 0, "short");
        assert(c.file_len == LS_RST_FILE_MAX - 1);                           n++;
        assert(c.file[LS_RST_FILE_MAX - 1] == '\0');                         n++;
    }

    /* 6. THE GUARD: a null file must produce a well-formed record carrying the
     *    verdict, never a fault. This runs during teardown. */
    ls_ctx_rst_build(&c, 0, 77, LS_ERR_EXPIRED, 3, "cause survives a null file");
    assert(c.file_len == 0 && c.file[0] == '\0');                            n++;
    assert(c.lineno == 77 && c.err == LS_ERR_EXPIRED && c.reason == 3);      n++;
    assert(shield(&c) == SAFE_RETURN);   /* still classifiable */            n++;

    /* 7. the record is fully overwritten between calls --- no bleed from the
     *    previous, longer, filename */
    ls_ctx_rst_build(&c, "/x/averylongfilename_aaaaaaaaaaaaaaaaaaaaaaa.c", 1,
                     LS_ERR_UNKNOWN, 0, "a very long cause string that will not fit in the field");
    ls_ctx_rst_build(&c, "/y/z.c", 2, LS_ERR_UNKNOWN, 0, "tiny");
    assert(strcmp(c.file, "z.c") == 0 && c.file_len == 3);                   n++;
    /* the cause must be overwritten too --- the previous call's was far longer */
    assert(strcmp(c.cause, "tiny") == 0 && c.cause_len == 4);                n++;

    /* --- 8. cause[]: the field Phase 3 forwards ------------------------------
     * rst_why's SIXTH argument. Before Phase 3 the trampoline passed five and this
     * was silently dropped; flow_table.c derives it from an enumerated table, so it
     * is not recoverable from the source. Same three failure modes as file[]. */
    ls_ctx_rst_build(&c, "flow_table.c", 2618, LS_ERR_REJECT, 0,
                     "No pool member available");
    assert(strcmp(c.cause, "No pool member available") == 0);                n++;
    assert(c.cause_len == 24 && c.lineno == 2618);                           n++;

    /* a null cause must not cost us the file, and must not fault */
    ls_ctx_rst_build(&c, "tcp.c", 4689, LS_ERR_UNKNOWN, 0, 0);
    assert(c.cause_len == 0 && c.cause[0] == '\0');                          n++;
    assert(strcmp(c.file, "tcp.c") == 0 && c.file_len == 5);                 n++;

    /* BOTH null --- the worst case on a teardown path, still a valid record */
    ls_ctx_rst_build(&c, 0, 5, LS_ERR_EXPIRED, 1, 0);
    assert(c.file_len == 0 && c.cause_len == 0 && c.lineno == 5);            n++;

    /* longer than the budget: truncated, NUL-terminated, never overrun */
    {
        char bigc[200];
        memset(bigc, 'c', sizeof bigc); bigc[sizeof bigc - 1] = '\0';
        ls_ctx_rst_build(&c, "x.c", 1, LS_ERR_UNKNOWN, 0, bigc);
        assert(c.cause_len == LS_RST_CAUSE_MAX - 1);                         n++;
        assert(c.cause[LS_RST_CAUSE_MAX - 1] == '\0');                       n++;
        /* and truncating the cause must not have touched file[] */
        assert(strcmp(c.file, "x.c") == 0);                                  n++;
    }

    printf("ok    ls_ctx_rst.h  (%d assertions: basename, truncation, null-file "
           "and null-cause guards, no bleed, 92 bytes under the 96 ceiling)\n", n);
    return 0;
}
