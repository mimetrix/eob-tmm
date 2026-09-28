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

#define LS_TARGET_SECTION ".ls.target"
#define LS_TARGET_MAGIC "LSTARG1"
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
            if (strcmp(name, section)) return -1;
            programs++;
        }
        if (strcmp(name, LS_TARGET_SECTION)) continue;
        if (++records != 1 || sh.sh_type != SHT_PROGBITS ||
            sh.sh_size != sizeof *out || (sh.sh_flags & SHF_EXECINSTR) ||
            !ls_target_span(len, sh.sh_offset, sh.sh_size)) return -1;
        memcpy(out, p + sh.sh_offset, sizeof *out);
    }
    if (records != 1 || programs != 1 || !build || strlen(build) != 40 ||
        memcmp(out->magic, LS_TARGET_MAGIC, 8) ||
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
#endif
