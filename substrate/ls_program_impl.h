/* Included only by ls_vm.c. Control calls are serialized by the loader.
 * A short reader gate protects publication and reclamation, not compilation. */
struct ls_owned_program {
    uint64_t instance;
    unsigned count, mode, ceiling;
    struct ls_map_namespace maps;
    struct ls_program_entry entries[LS_PROGRAM_ENTRIES];
    int sites[LS_PROGRAM_ENTRIES];
};
static struct {
    _Atomic unsigned writer, readers;
    struct ls_owned_program programs[LS_PROGRAM_MAX];
    struct {
        uint64_t address, return_ip, safe_value;
        unsigned users;
        /* Atomic because a busy dispatcher must distinguish this from a legacy site. */
        _Atomic unsigned owned;
    } sites[LS_PROGRAM_SITES];
} g_programs;

static int
ls_program_lock(void)
{
    if (atomic_exchange(&g_programs.writer, 1))
        return -1;
    if (atomic_load(&g_programs.readers)) {
        atomic_store(&g_programs.writer, 0);
        return -1;
    }
    return 0;
}

static void ls_program_unlock(void) { atomic_store(&g_programs.writer, 0); }

static struct ls_owned_program *
ls_program_find(unsigned id, uint64_t instance)
{
    if (id >= LS_PROGRAM_MAX || !instance ||
        g_programs.programs[id].instance != instance)
        return NULL;
    return &g_programs.programs[id];
}

static unsigned
ls_program_slot(unsigned id, unsigned entry)
{
    return LS_LEGACY_SLOTS + id * LS_PROGRAM_ENTRIES + entry;
}

int
ls_program_status(unsigned id, struct ls_program_status *out)
{
    if (id >= LS_PROGRAM_MAX || !out)
        return -1;
    struct ls_owned_program *p = &g_programs.programs[id];
    *out = (struct ls_program_status){p->instance, p->count, 0, p->mode,
                                      LS_PROGRAM_CONFIG_BASE + id};
    for (unsigned i = 0; i < p->count; i++)
        out->attached += p->sites[i] >= 0;
    return 0;
}

int
ls_program_load(unsigned id, const void *elf, size_t len,
                const struct ls_program_entry *entries, unsigned count,
                const uint8_t sha[32], unsigned ceiling)
{
    if (id >= LS_PROGRAM_MAX || !count || count > LS_PROGRAM_ENTRIES ||
        !elf || !entries || !sha || ceiling > LS_MODE_ENFORCE)
        return -1;
    struct ls_owned_program *p = &g_programs.programs[id];
    if (p->instance || p->maps.generation == ((1ull << 55) - 1))
        return -1;
    for (unsigned i = 0; i < count; i++) {
        if (!memchr(entries[i].section, 0, sizeof entries[i].section) ||
            strncmp(entries[i].section, "fentry/", 7) || !entries[i].section[7] ||
            !entries[i].address || (entries[i].pad != 0 && entries[i].pad != 4) ||
            entries[i].address > UINT64_MAX - entries[i].pad - 5)
            return -1;
        for (unsigned j = 0; j < i; j++)
            if (!strcmp(entries[i].section, entries[j].section) ||
                entries[i].address == entries[j].address)
                return -1;
    }
    unsigned config = LS_PROGRAM_CONFIG_BASE + id;
    uint64_t instance = ls_config_new_instance(&g_ls_config, config);
    if (!instance)
        return -1;
    /* This bank has no published program. Compilation does not block other
     * programs and cannot change their maps or configuration. */
    uint64_t generation = p->maps.generation + 1;
    memset(&p->maps, 0, sizeof p->maps);
    p->maps.bank = id;
    p->maps.generation = generation;
    unsigned made = 0;
    g_ls_namespace = &p->maps;
    g_ls_config.loading = instance;
    for (; made < count; made++) {
        unsigned slot = ls_program_slot(id, made);
        char function[64];
        memset(&g_slots[slot], 0, sizeof g_slots[slot]);
        g_slots[slot].owner = id + 1;
        if (!ls_function_in_section(elf, len, entries[made].section,
                                    function, sizeof function) ||
            ls_vm_prepare_slot((int)slot, elf, len, entries[made].section,
                                function, LS_MODE_DISABLE) < 0)
            break;
        p->entries[made] = entries[made];
        p->sites[made] = -1;
    }
    g_ls_config.loading = 0;
    g_ls_namespace = NULL;
    if (made == count && ls_program_lock() == 0) {
        if (ls_config_bind(&g_ls_config, config, instance, sha) == 0) {
            p->count = count;
            p->ceiling = ceiling;
            p->instance = instance;
            ls_program_unlock();
            return 0;
        }
        ls_program_unlock();
    }
    for (unsigned i = 0; i < made; i++) {
        unsigned slot = ls_program_slot(id, i);
        ubpf_destroy(g_slots[slot].vm);
        memset(&g_slots[slot], 0, sizeof g_slots[slot]);
    }
    return -1;
}

int
ls_program_site_owned(unsigned site, uint64_t address)
{
    for (unsigned i = 0; i < LS_PROGRAM_SITES; i++)
        if (atomic_load(&g_programs.sites[i].owned) &&
            (site == i || (address && g_programs.sites[i].address == address)))
            return 1;
    return 0;
}

int
ls_program_mode(unsigned id, uint64_t instance, unsigned mode)
{
    struct ls_owned_program *p = ls_program_find(id, instance);
    if (!p || mode > p->ceiling || ls_program_lock() != 0)
        return -1;
    p->mode = mode;
    for (unsigned i = 0; i < p->count; i++)
        g_slots[ls_program_slot(id, i)].mode = (enum ls_mode)mode;
    ls_program_unlock();
    return 0;
}

int
ls_program_attach(unsigned id, uint64_t instance, unsigned entry,
                  ls_program_patch_fn patch)
{
    struct ls_owned_program *p = ls_program_find(id, instance);
    if (!p || entry >= p->count || p->sites[entry] >= 0 || !patch ||
        ls_program_lock() != 0)
        return -1;
    uint64_t address = p->entries[entry].address;
    uint64_t safe = g_slots[ls_program_slot(id, entry)].safe_value;
    int site = -1, rc = -1;
    for (unsigned i = 0; i < LS_PROGRAM_SITES; i++) {
        if (g_programs.sites[i].users &&
            g_programs.sites[i].address == address) {
            if (g_programs.sites[i].safe_value != safe)
                goto out;
            site = (int)i;
            break;
        }
    }
    if (site < 0) {
        for (unsigned i = 0; i < LS_PROGRAM_SITES; i++) {
            if (g_programs.sites[i].users)
                continue;
            /* The callback also checks legacy ownership before changing text. */
            if (patch(address, i, 1) != 0)
                continue;
            site = (int)i;
            g_programs.sites[i].address = address;
            g_programs.sites[i].return_ip = address + p->entries[entry].pad + 5;
            g_programs.sites[i].safe_value = safe;
            atomic_store(&g_programs.sites[i].owned, 1);
            break;
        }
    }
    if (site >= 0) {
        p->sites[entry] = site;
        g_programs.sites[site].users++;
        rc = 0;
    }
out:
    ls_program_unlock();
    return rc;
}

/* Requires the control gate. Keep the link on restore failure, for retry. */
static int
ls_program_detach_locked(struct ls_owned_program *p, unsigned entry,
                         ls_program_patch_fn patch)
{
    int site = p->sites[entry];
    if (site < 0)
        return -1;
    if (g_programs.sites[site].users == 1) {
        if (patch(g_programs.sites[site].address, (unsigned)site, 0) != 0)
            return -1;
        /* Keep the dispatcher reservation. A thread can be paused between the
         * assembly entry and our reader gate. It must never fall into a legacy
         * slot after this site is detached. Managed reuse checks return_ip. */
    }
    g_programs.sites[site].users--;
    p->sites[entry] = -1;
    return 0;
}

int
ls_program_detach(unsigned id, uint64_t instance, unsigned entry,
                  ls_program_patch_fn patch)
{
    struct ls_owned_program *p = ls_program_find(id, instance);
    if (!p || entry >= p->count || !patch || ls_program_lock() != 0)
        return -1;
    int rc = ls_program_detach_locked(p, entry, patch);
    ls_program_unlock();
    return rc;
}

int
ls_program_revoke(unsigned id, uint64_t instance, ls_program_patch_fn patch)
{
    struct ls_owned_program *p = ls_program_find(id, instance);
    if (!p || !patch || ls_program_lock() != 0)
        return -1;
    p->mode = LS_MODE_DISABLE;
    for (unsigned i = 0; i < p->count; i++)
        g_slots[ls_program_slot(id, i)].mode = LS_MODE_DISABLE;
    for (unsigned i = 0; i < p->count; i++) {
        if (p->sites[i] >= 0 && ls_program_detach_locked(p, i, patch) != 0) {
            ls_program_unlock();
            return -1;
        }
    }
    if (ls_config_revoke(&g_ls_config, LS_PROGRAM_CONFIG_BASE + id) != 0) {
        ls_program_unlock();
        return -1;
    }
    for (unsigned i = 0; i < p->count; i++) {
        unsigned slot = ls_program_slot(id, i);
        ubpf_destroy(g_slots[slot].vm);
        memset(&g_slots[slot], 0, sizeof g_slots[slot]);
    }
    p->instance = 0;
    p->count = 0;
    ls_program_unlock();
    return 0;
}

int
ls_program_dispatch(unsigned site, uint64_t return_ip,
                    const struct ls_ctx_generic *input, struct ls_tramp_result *out)
{
    if (site >= LS_PROGRAM_SITES)
        return 0;
    *out = (struct ls_tramp_result){LS_FALLTHROUGH, 0};
    atomic_fetch_add(&g_programs.readers, 1);
    if (atomic_load(&g_programs.writer)) {
        atomic_fetch_sub(&g_programs.readers, 1);
        return 1;
    }
    int owned = atomic_load(&g_programs.sites[site].owned);
    if (owned && return_ip == g_programs.sites[site].return_ip && input &&
        !g_ls_namespace && g_ls_cur_slot < 0) {
        for (unsigned id = 0; id < LS_PROGRAM_MAX; id++) {
            struct ls_owned_program *p = &g_programs.programs[id];
            if (!p->instance || p->mode == LS_MODE_DISABLE)
                continue;
            for (unsigned i = 0; i < p->count; i++) {
                if (p->sites[i] != (int)site)
                    continue;
                struct ls_ctx_generic ctx = *input;
                g_ls_namespace = &p->maps;
                if (ls_vm_run((int)ls_program_slot(id, i), &ctx, sizeof ctx,
                              NULL, NULL) == LS_SAFE_RETURN) {
                    out->verdict = LS_SAFE_RETURN;
                    out->safe_value = g_programs.sites[site].safe_value;
                }
                g_ls_namespace = NULL;
            }
        }
    }
    atomic_fetch_sub(&g_programs.readers, 1);
    return owned;
}
