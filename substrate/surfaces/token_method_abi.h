/* Local layouts qualified against the pinned ca69b84f debug image. */
#ifndef TOKEN_METHOD_ABI_H
#define TOKEN_METHOD_ABI_H
#include "json_method_abi.h"
#define TM_MAGIC 0x544d4554u
#define TM_NO_LITERAL_METHOD 8u
#define TM_INVALID_CACHE 9u
#define TM_NONSTRING 10u
struct tm_token { int type, start, end, size, sibling; };
struct tm_frag {
    jm_u32 magic;
    unsigned short len, offset;
    jm_u64 base, next;
};
/* jm_event's getter_result word carries root_members for this schema. */
#endif
