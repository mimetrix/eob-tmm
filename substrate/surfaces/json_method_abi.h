/* Fixed to the ca69b84f package's debug types; not a portable TMM ABI. */
#ifndef JSON_METHOD_ABI_H
#define JSON_METHOD_ABI_H
typedef unsigned int jm_u32;
typedef unsigned long long jm_u64;
enum jm_status {
    JM_COMPLETE = 1, JM_TRUNCATED, JM_READ_FAILED, JM_OUT_OF_SCOPE,
    JM_BUDGET, JM_GETTER_ERROR, JM_UNAVAILABLE
};
struct jm_event {
    jm_u32 magic, abi;
    jm_u64 instance, revision, run, monotonic_ns, sequence, output_failures;
    jm_u32 status, getter_result, original_length, copied_length;
    unsigned short flags, reads;
    jm_u32 source_bytes;
    unsigned char value[64];
};
/* Local read buffers. No complete object or address is exported. */
struct jm_value {
    jm_u32 type, pad;
    jm_u64 value[2];
    jm_u32 flags, token;
    jm_u64 cache, owner;
};
struct jm_member {
    jm_u64 key;
    jm_u32 len, pad, token, flags;
    jm_u64 value, next;
};
_Static_assert(sizeof(struct jm_event) == 144, "record ABI");
_Static_assert(sizeof(struct jm_value) == 48, "value layout");
_Static_assert(sizeof(struct jm_member) == 40, "member prefix layout");
#endif
