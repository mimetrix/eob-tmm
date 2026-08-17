/*
 * frida-reloc-survey.c --- what fraction of TMM's functions can Frida relocate?
 *
 * The in-TMM experiment proved Frida hooks ONE unpadded function (EVP_EncryptUpdate).
 * That proves the mechanism, not the population. Inline hooking works by displacing
 * the first bytes of a function and relocating them elsewhere, so whether it is safe
 * depends entirely on WHICH instructions get displaced --- and TMM has ~74,000 of them.
 *
 * The dangerous shapes are known: a branch target landing inside the displaced range,
 * an instruction that cannot be re-encoded at a different address, or a function whose
 * first bytes are shorter than the 5 needed for a jmp rel32.
 *
 * This asks Frida's own relocator about each real function entry in the shipped
 * binary, rather than guessing. No TMM process is involved --- the binary is mapped
 * read-only and analysed.
 *
 * WHY THE ADDRESSES ARE USABLE AS-IS: tmm.no_pgo is linked -no-pie, so a symbol's
 * st_value IS its runtime address. Relative displacements therefore resolve to the
 * same places the relocator would see at run time.
 */
#include "frida-gum.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define NEED_BYTES 5              /* jmp rel32 --- what an inline hook must displace */

int
main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "tmm.no_pgo";
    int fd;
    struct stat st;
    unsigned char *map;
    Elf64_Ehdr *eh;
    Elf64_Shdr *sh;
    const char *shstr;
    Elf64_Sym *syms = NULL;
    const char *strtab = NULL;
    size_t nsyms = 0, i;
    unsigned long total = 0, ok = 0, too_short = 0, failed = 0;
    unsigned long padded = 0;

    if ((fd = open(path, O_RDONLY)) < 0) { perror(path); return 2; }
    fstat(fd, &st);
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 2; }

    eh = (Elf64_Ehdr *)map;
    sh = (Elf64_Shdr *)(map + eh->e_shoff);
    shstr = (const char *)(map + sh[eh->e_shstrndx].sh_offset);

    for (i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB) {
            syms = (Elf64_Sym *)(map + sh[i].sh_offset);
            nsyms = sh[i].sh_size / sizeof(Elf64_Sym);
            strtab = (const char *)(map + sh[sh[i].sh_link].sh_offset);
        }
    }
    if (!syms) { fprintf(stderr, "no symtab in %s --- use the unstripped binary\n", path); return 2; }
    (void)shstr;

    gum_init_embedded();

    for (i = 0; i < nsyms; i++) {
        Elf64_Sym *s = &syms[i];
        unsigned long vaddr = s->st_value;
        unsigned char *code = NULL;
        size_t j;
        GumX86Relocator rl;
        GumX86Writer wr;
        unsigned char outbuf[256];
        guint reloc_bytes = 0;
        int is_padded;

        if (ELF64_ST_TYPE(s->st_info) != STT_FUNC || s->st_size < 16 || vaddr == 0)
            continue;

        /* vaddr -> file offset, via the section that contains it */
        for (j = 0; j < eh->e_shnum; j++) {
            if ((sh[j].sh_flags & SHF_EXECINSTR) && vaddr >= sh[j].sh_addr &&
                vaddr < sh[j].sh_addr + sh[j].sh_size) {
                code = map + sh[j].sh_offset + (vaddr - sh[j].sh_addr);
                break;
            }
        }
        if (!code) continue;

        total++;

        is_padded = (code[0] == 0xf3 && code[1] == 0x0f && code[2] == 0x1e &&
                     code[3] == 0xfa && code[4] == 0x90 && code[5] == 0x90) ||
                    (code[0] == 0x90 && code[1] == 0x90 && code[2] == 0x90 &&
                     code[3] == 0x90 && code[4] == 0x90);
        if (is_padded) padded++;

        /* Ask Frida: can it read and re-emit at least NEED_BYTES from this entry?
         * The writer targets a scratch buffer at a DIFFERENT address, which is the
         * point --- relocation is exactly the act of re-encoding for a new location. */
        gum_x86_writer_init(&wr, outbuf);
        gum_x86_relocator_init(&rl, code, &wr);

        while (reloc_bytes < NEED_BYTES) {
            guint n = gum_x86_relocator_read_one(&rl, NULL);
            if (n == 0) break;                  /* relocator refused to read further */
            reloc_bytes = n;
            if (gum_x86_relocator_eob(&rl)) break;   /* end of block: a branch */
        }

        if (reloc_bytes < NEED_BYTES) {
            too_short++;
        } else if (!gum_x86_relocator_write_all(&rl)) {
            failed++;
        } else {
            ok++;
        }

        gum_x86_relocator_clear(&rl);
        gum_x86_writer_clear(&wr);
    }

    printf("=== Frida relocation survey: %s ===\n", path);
    printf("  functions examined            : %lu\n", total);
    printf("  already PADDED (we can arm)   : %lu  (%.1f%%)\n",
           padded, total ? 100.0 * padded / total : 0.0);
    printf("\n  Frida CAN relocate >=%d bytes : %lu  (%.1f%%)\n",
           NEED_BYTES, ok, total ? 100.0 * ok / total : 0.0);
    printf("  refused --- too short/branch   : %lu  (%.1f%%)\n",
           too_short, total ? 100.0 * too_short / total : 0.0);
    printf("  refused --- write_all failed   : %lu  (%.1f%%)\n",
           failed, total ? 100.0 * failed / total : 0.0);

    gum_deinit_embedded();
    munmap(map, st.st_size);
    close(fd);
    return 0;
}
