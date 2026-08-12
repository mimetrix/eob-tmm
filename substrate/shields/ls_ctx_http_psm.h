/* GENERATED from tmm64.no_pgo.debug DWARF -- do not hand-edit.
 * hook: http_psm_profile_name_lookup  (static bool, survives -O2 as type 't')
 * The trampoline resolves the pointer chain the C code walks and hands the
 * shield a flat, bounded ctx: eBPF cannot chase unbounded pointers and PREVAIL
 * will not admit a program that tries.
 */
#ifndef LS_CTX_HTTP_PSM_H
#define LS_CTX_HTTP_PSM_H
typedef unsigned long long __u64;
typedef unsigned int       __u32;

struct ls_ctx_http_psm {
    __u64 ptlp;            /* struct fw_log_profile_protocol_transfer * -- MAY BE NULL */
    __u64 ptlp_name;       /* ptlp->name, offset 0 in that struct        -- MAY BE NULL */
    __u32 errdefs_key;     /* arg0: enum errdefs_key */
    __u32 name_len;        /* trampoline-measured, 0 if name is NULL */
};
#define LS_FALLTHROUGH  0u
#define LS_SAFE_RETURN  1u
#endif
