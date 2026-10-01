/* Build-resolved attachment record. It lives in .ls.target in the program ELF,
 * hence inside the SHA-256 authenticated by the existing Ed25519 binding. No
 * wire-layout change and no function/type catalog on the deployed host.
 *
 * Version 1 deliberately admits only ELF64 little-endian ET_EXEC x86-64 targets
 * with a 20-byte GNU build ID and a +0/+4 five-NOP entry pad. PIE needs a separate
 * load-bias contract. Return ABI/unwind admission remains the signer's job.
 */
#ifndef LS_TARGET_H
#define LS_TARGET_H
#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "ls_snapshot.h"
#include "ls_program.h"

#define LS_TARGET_SECTION ".ls.target"
#define LS_TARGET_MAGIC "LSTARG1"
#define LS_TARGET_SNAPSHOT_MAGIC "LSTARG2"
#define LS_TARGET_SET_MAGIC "LSTSET1"
#define LS_TARGET_SET_MAX 12u
struct ls_target {
    char magic[8];
    char build_id[40];             /* full lowercase GNU build ID, no terminator */
    uint64_t entry;                /* function entry, NOT the +4 patch address */
    uint8_t is_exit;
    uint8_t pad_offset;
    uint8_t reserved[6];
};
_Static_assert(sizeof(struct ls_target) == 64, "target record size");
_Static_assert(offsetof(struct ls_target, entry) == 48, "target entry offset");

/* Entry-only multi-program ELF. Each section has exactly one signed target.
 * The loader still loads one selected section per slot. No atomic group arm. */
struct ls_target_set_header {
    char magic[8];
    uint32_t count, reserved;
};
struct ls_target_set_row {
    char section[80];
    struct ls_target target;
};
_Static_assert(sizeof(struct ls_target_set_header) == 16, "target set header");
_Static_assert(sizeof(struct ls_target_set_row) == 144, "target set row");

static int
ls_target_span(size_t len, uint64_t off, uint64_t size)
{
    return off <= len && size <= len - off;
}

/* Parse only bounded bytes, including section names; reject duplicate records.
 * Called after signature verification, but a signed malformed ELF still fails. */
static int
ls_target_parse(const void *elf, size_t len, const char *section,
                const char *build, struct ls_target *out)
{
    const unsigned char *p = elf;
    Elf64_Ehdr e;
    Elf64_Shdr strings, sh;
    unsigned records = 0, programs = 0;
    const unsigned char *record = NULL;
    size_t record_len = 0;
    const char *names[LS_TARGET_SET_MAX];
    if (len < sizeof e) return -1;
    memcpy(&e, p, sizeof e);
    if (memcmp(e.e_ident, ELFMAG, SELFMAG) || e.e_ident[EI_CLASS] != ELFCLASS64 ||
        e.e_ident[EI_DATA] != ELFDATA2LSB || e.e_machine != EM_BPF ||
        e.e_type != ET_REL || e.e_shentsize != sizeof sh ||
        !e.e_shnum || e.e_shstrndx >= e.e_shnum ||
        !ls_target_span(len, e.e_shoff, (uint64_t)e.e_shnum * sizeof sh)) return -1;
    memcpy(&strings, p + e.e_shoff + e.e_shstrndx * sizeof sh, sizeof sh);
    if (strings.sh_type != SHT_STRTAB ||
        !ls_target_span(len, strings.sh_offset, strings.sh_size)) return -1;
    for (unsigned i = 0; i < e.e_shnum; i++) {
        memcpy(&sh, p + e.e_shoff + i * sizeof sh, sizeof sh);
        if (sh.sh_name >= strings.sh_size) return -1;
        const char *name = (const char *)p + strings.sh_offset + sh.sh_name;
        if (!memchr(name, 0, strings.sh_size - sh.sh_name)) return -1;
        if (!strncmp(name, "fentry/", 7) || !strncmp(name, "fexit/", 6)) {
            if (programs == LS_TARGET_SET_MAX ||
                sh.sh_type != SHT_PROGBITS || !(sh.sh_flags & SHF_EXECINSTR) ||
                !sh.sh_size || sh.sh_size % 8 ||
                !ls_target_span(len, sh.sh_offset, sh.sh_size)) return -1;
            for (unsigned j = 0; j < programs; j++)
                if (!strcmp(name, names[j])) return -1;
            names[programs++] = name;
        }
        if (strcmp(name, LS_TARGET_SECTION)) continue;
        if (++records != 1 || sh.sh_type != SHT_PROGBITS ||
            (sh.sh_flags & SHF_EXECINSTR) ||
            !ls_target_span(len, sh.sh_offset, sh.sh_size)) return -1;
        record = p + sh.sh_offset;
        record_len = sh.sh_size;
    }
    if (records != 1 || !programs || !build || strlen(build) != 40)
        return -1;
    if (record_len == sizeof *out) {
        if (programs != 1 || strcmp(names[0], section)) return -1;
        memcpy(out, record, sizeof *out);
    } else {
        struct ls_target_set_header header;
        unsigned seen = 0, selected = 0;
        uint64_t entries[LS_TARGET_SET_MAX];
        if (record_len < sizeof header) return -1;
        memcpy(&header, record, sizeof header);
        if (memcmp(header.magic, LS_TARGET_SET_MAGIC, 8) || header.reserved ||
            header.count != programs || header.count < 2 ||
            record_len != sizeof header +
                header.count * sizeof(struct ls_target_set_row)) return -1;
        for (unsigned i = 0; i < header.count; i++) {
            struct ls_target_set_row row;
            memcpy(&row, record + sizeof header + i * sizeof row, sizeof row);
            const char *nul = memchr(row.section, 0, sizeof row.section);
            if (!nul || strncmp(row.section, "fentry/", 7) ||
                !row.section[7] ||
                memcmp(row.target.magic, LS_TARGET_MAGIC, 8) ||
                memcmp(row.target.build_id, build, 40) ||
                !row.target.entry || row.target.is_exit ||
                (row.target.pad_offset != 0 && row.target.pad_offset != 4))
                return -1;
            for (const char *q = nul; q < row.section + sizeof row.section; q++)
                if (*q) return -1;
            for (unsigned j = 0; j < sizeof row.target.reserved; j++)
                if (row.target.reserved[j]) return -1;
            for (unsigned j = 0; j < i; j++)
                if (entries[j] == row.target.entry) return -1;
            entries[i] = row.target.entry;
            unsigned j = 0;
            while (j < programs && strcmp(row.section, names[j])) j++;
            if (j == programs || (seen & (1u << j))) return -1;
            seen |= 1u << j;
            if (!strcmp(row.section, section)) {
                *out = row.target;
                selected++;
            }
        }
        if (selected != 1 || seen != (1u << programs) - 1) return -1;
    }
    int snapshot = strncmp(section, LS_SNAPSHOT_SECTION,
                           LS_SNAPSHOT_PREFIX_LEN) == 0;
    if (memcmp(out->magic, snapshot ? LS_TARGET_SNAPSHOT_MAGIC :
                                     LS_TARGET_MAGIC, 8) ||
        (snapshot && !section[LS_SNAPSHOT_PREFIX_LEN]) ||
        memcmp(out->build_id, build, 40) || !out->entry ||
        out->is_exit > 1 || out->is_exit != (strncmp(section, "fexit/", 6) == 0) ||
        (out->pad_offset != 0 && out->pad_offset != 4)) return -1;
    for (unsigned i = 0; i < sizeof out->reserved; i++)
        if (out->reserved[i]) return -1;
    return 0;
}

/* Check the signed address against the executing file's executable segments and
 * original pad bytes before any direct dereference of that address is allowed.
 * Read the file, not mutable live text: same-target program replacement can
 * happen while the entry is patched. ls_arm_live separately checks live NOPs. */
static int
ls_target_check_file(const char *path, const struct ls_target *t)
{
    Elf64_Ehdr e;
    Elf64_Phdr ph;
    unsigned char bytes[9];
    const unsigned char expected[9] = {0xf3,0x0f,0x1e,0xfa,0x90,0x90,0x90,0x90,0x90};
    size_t need = t->pad_offset + 5;
    int rc = -1, fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    if (pread(fd, &e, sizeof e, 0) != sizeof e ||
        memcmp(e.e_ident, ELFMAG, SELFMAG) || e.e_ident[EI_CLASS] != ELFCLASS64 ||
        e.e_ident[EI_DATA] != ELFDATA2LSB || e.e_type != ET_EXEC ||
        e.e_machine != EM_X86_64 || e.e_phentsize != sizeof ph ||
        e.e_phoff > INT64_MAX || e.e_phnum > 1024 ||
        (t->pad_offset != 0 && t->pad_offset != 4)) goto out;
    for (unsigned i = 0; i < e.e_phnum; i++) {
        uint64_t off = e.e_phoff + (uint64_t)i * sizeof ph;
        if (off > INT64_MAX || pread(fd, &ph, sizeof ph, (off_t)off) != sizeof ph) goto out;
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X) || t->entry < ph.p_vaddr) continue;
        uint64_t delta = t->entry - ph.p_vaddr;
        if (delta > ph.p_filesz || need > ph.p_filesz - delta ||
            ph.p_offset > INT64_MAX || delta > INT64_MAX - ph.p_offset) continue;
        if (pread(fd, bytes, need, (off_t)(ph.p_offset + delta)) != (ssize_t)need) goto out;
        rc = memcmp(bytes, expected + (t->pad_offset ? 0 : 4), need) ? -1 : 0;
        break;
    }
out:
    close(fd);
    return rc;
}

/* Enumerate the entry programs in one ELF. Each selected name is then checked
 * by the full target parser, including the other signed rows and their builds. */
static inline int
ls_target_program_entries(const void *elf, size_t len, const char *build,
                           const char *binary, struct ls_program_entry *out)
{
    const unsigned char *p = elf;
    Elf64_Ehdr e;
    Elf64_Shdr strings, sh;
    unsigned count = 0;
    if (!p || !out || len < sizeof e)
        return -1;
    memcpy(&e, p, sizeof e);
    if (e.e_shentsize != sizeof sh || !e.e_shnum || e.e_shstrndx >= e.e_shnum ||
        !ls_target_span(len, e.e_shoff, (uint64_t)e.e_shnum * sizeof sh))
        return -1;
    memcpy(&strings, p + e.e_shoff + e.e_shstrndx * sizeof sh, sizeof sh);
    if (!ls_target_span(len, strings.sh_offset, strings.sh_size))
        return -1;
    for (unsigned i = 0; i < e.e_shnum; i++) {
        memcpy(&sh, p + e.e_shoff + i * sizeof sh, sizeof sh);
        if (sh.sh_name >= strings.sh_size)
            return -1;
        const char *name = (const char *)p + strings.sh_offset + sh.sh_name;
        if (!memchr(name, 0, strings.sh_size - sh.sh_name))
            return -1;
        if (!strncmp(name, "fexit/", 6))
            return -1;
        if (strncmp(name, "fentry/", 7))
            continue;
        struct ls_target target;
        if (count == LS_PROGRAM_ENTRIES || strlen(name) >= sizeof out[count].section ||
            ls_target_parse(elf, len, name, build, &target) != 0 ||
            ls_target_check_file(binary, &target) != 0)
            return -1;
        memset(&out[count], 0, sizeof out[count]);
        strcpy(out[count].section, name);
        out[count].address = target.entry;
        out[count].pad = target.pad_offset;
        count++;
    }
    return count ? (int)count : -1;
}
#endif
