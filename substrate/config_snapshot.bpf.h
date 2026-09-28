/* Program-side configuration ABI v1. No libc/kernel headers required. */
#ifndef LS_CONFIG_BPF_H
#define LS_CONFIG_BPF_H
typedef unsigned int ls_cfg_u32;
typedef unsigned long long ls_cfg_u64;
struct ls_cfg_meta {
    ls_cfg_u64 revision, instance;
    ls_cfg_u32 schema, entries;
    ls_cfg_u64 reserved;
};
struct ls_cfg_map_def {
    ls_cfg_u32 type, key_size, value_size, max_entries, map_flags;
};
/* A dedicated ARRAY view; does not occupy the legacy four-map registry.
 * Keep the ELF symbol GLOBAL: with static/local symbols clang relocates via the
 * section, and pinned PREVAIL refuses the helper argument as not a map_fd. */
struct ls_cfg_map_def ls_config_v1 __attribute__((section("maps"), used)) = {
    2, 4, 32, 17, 128
};
static void *(*ls_cfg_lookup_helper)(void *, const void *) = (void *)1;
static __attribute__((always_inline)) inline void *ls_cfg_get(ls_cfg_u32 index)
{
    return ls_cfg_lookup_helper(&ls_config_v1, &index);
}
#endif
