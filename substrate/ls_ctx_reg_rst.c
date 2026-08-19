/* ls_ctx_reg_rst.c --- the four reset functions register their builders.
 *
 * Four registrations and one builder pair, because RST_WHY* expands to four functions across
 * 1,090 call sites and they come in TWO SHAPES:
 *
 *   rst_why         (uf, file, lineno, err, reason, cause)   cause in a5
 *   rst_why_va      (uf, file, lineno, err, reason, cause, fmt, ...)   same first six
 *   rst_why_preserve(uf, file, lineno, err, cause)           cause in a4 --- no `reason`
 *   rst_why_preserve_va                                      same as preserve
 *
 * The va forms share their non-va sibling's builder verbatim: their varargs start at the
 * seventh argument and nothing here reads past the sixth.
 *
 * THE PRESERVE PAIR IS A DIFFERENT BUILDER, not a flag. It has no `reason`, so everything
 * after `err` shifts down one. Reading a5 there hands the record whatever the caller left in
 * r9 --- a plausible-looking pointer dereferenced as a string, which is the worst shape of
 * wrong and the reason these are four entries rather than one with a conditional.
 *
 * Each entry names its own hook_id so a consumer can tell which of the four fired. That used
 * to be derived from the slot, which is exactly what broke.
 */
#include "ls_ctx_reg.h"
#include "ls_ctx_rst.h"
#include "ls_tp.h"

extern unsigned long long ls_uflow_cookie(void *uf);

static unsigned long
build_rst(void *out, const unsigned long long *a)
{
    ls_ctx_rst_build((struct ls_ctx_rst *)out, (const char *)a[1], (unsigned int)a[2],
                     (unsigned int)a[3], (unsigned int)a[4], (const char *)a[5],
                     ls_uflow_cookie((void *)a[0]));
    return sizeof(struct ls_ctx_rst);
}

static unsigned long
build_rst_preserve(void *out, const unsigned long long *a)
{
    /* reason is 0 and the cause is a4. See the header comment. */
    ls_ctx_rst_build((struct ls_ctx_rst *)out, (const char *)a[1], (unsigned int)a[2],
                     (unsigned int)a[3], 0u, (const char *)a[4],
                     ls_uflow_cookie((void *)a[0]));
    return sizeof(struct ls_ctx_rst);
}

static const struct ls_ctx_reg reg_rst = {
    "rst_why", build_rst, sizeof(struct ls_ctx_rst), LS_TP_HOOK_RST
};
static const struct ls_ctx_reg reg_rst_va = {
    "rst_why_va", build_rst, sizeof(struct ls_ctx_rst), LS_TP_HOOK_RST_VA
};
static const struct ls_ctx_reg reg_rst_pre = {
    "rst_why_preserve", build_rst_preserve, sizeof(struct ls_ctx_rst), LS_TP_HOOK_RST_PRE
};
static const struct ls_ctx_reg reg_rst_pre_va = {
    "rst_why_preserve_va", build_rst_preserve, sizeof(struct ls_ctx_rst),
    LS_TP_HOOK_RST_PRE_VA
};

LS_CTX_REGISTER(reg_rst);
LS_CTX_REGISTER(reg_rst_va);
LS_CTX_REGISTER(reg_rst_pre);
LS_CTX_REGISTER(reg_rst_pre_va);

_Static_assert(sizeof(struct ls_ctx_rst) <= LS_CTX_OUT_MAX,
               "the reset record no longer fits the trampoline's ctx buffer");
