/* The BPF-side view of the parse ctx. Layout MUST match substrate/ls_ctx_parse.h
 * field for field --- the host writes that struct, the program reads this one,
 * and nothing checks they agree. Keeping them in two files is the price of the
 * program compiling for the bpf target while the host side compiles for x86-64.
 *
 * The static asserts below pin the size, which catches the drift that matters:
 * a field added on one side and not the other.
 */
#ifndef LS_CTX_PARSE_BPF_H
#define LS_CTX_PARSE_BPF_H
typedef unsigned int ls_u32;

struct ls_ctx_parse {
    ls_u32 state;
    ls_u32 offset;
    ls_u32 version;
    ls_u32 method;
    ls_u32 header_count;
    ls_u32 status_code;
    ls_u32 invalid_flags;
};
_Static_assert(sizeof(struct ls_ctx_parse) == 28, "must match ls_ctx_parse.h");

#define LS_FALLTHROUGH  0u
#define LS_SAFE_RETURN  1u
#endif
