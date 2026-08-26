/* ls_core_relo.c --- CO-RE field-offset relocation, no libbpf/kernel deps.
 *
 * A portable program names TMM fields by struct+field NAME and carries .BTF +
 * .BTF.ext relocation records. ls_core_relocate() resolves each field's byte
 * offset against THIS build's BTF and patches the instruction immediate, so one
 * bytecode runs on any build with no baked offsets and no rebuild.
 *
 * Scope: kind=0 FIELD_BYTE_OFFSET, the only kind our compiler emits for
 * preserve_access_index field reads. Every other kind is rejected (fail-dark):
 * the caller MUST refuse to load on a non-zero return.
 *
 * ALL input here is untrusted-ish (a program handed over a socket, in a security
 * appliance), so every ELF/BTF/.BTF.ext offset is bounds-checked against the
 * buffer before use. Reads are byte-assembled (RD16/32/64) --- no unaligned casts.
 *
 * BTF and .BTF.ext binary layout per kernel Documentation/bpf/btf.rst.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ls_core_relo.h"

/* ---- BTF on-disk ---- */
enum { BTF_MAGIC = 0xeB9F };
enum { KIND_INT=1,KIND_PTR=2,KIND_ARRAY=3,KIND_STRUCT=4,KIND_UNION=5,KIND_ENUM=6,
       KIND_FWD=7,KIND_TYPEDEF=8,KIND_VOLATILE=9,KIND_CONST=10,KIND_RESTRICT=11,
       KIND_FUNC=12,KIND_FUNC_PROTO=13,KIND_VAR=14,KIND_DATASEC=15,KIND_FLOAT=16,
       KIND_DECL_TAG=17,KIND_TYPE_TAG=18,KIND_ENUM64=19 };

struct btf_hdr { uint16_t magic; uint8_t version; uint8_t flags; uint32_t hdr_len;
                 uint32_t type_off, type_len, str_off, str_len; };
struct btf_type { uint32_t name_off; uint32_t info; uint32_t size_or_type; };
struct btf_member { uint32_t name_off; uint32_t type; uint32_t offset; };

#define KIND(t)      (((t)->info >> 24) & 0x1f)
#define VLEN(t)      ((t)->info & 0xffff)
#define KFLAG(t)     (((t)->info >> 31) & 1)

/* little-endian byte-assembled reads (BTF/ELF are LE) --- alignment-safe */
static uint16_t rd16(const uint8_t *p){ return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t rd32(const uint8_t *p){ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t rd64(const uint8_t *p){ return (uint64_t)rd32(p)|((uint64_t)rd32(p+4)<<32); }

static const char *btf_str(const struct btf *b, uint32_t off) {
    return off < b->strs_len ? b->strs + off : "";
}
static const struct btf_type *btf_type_by_id(const struct btf *b, uint32_t id) {
    if (id == 0 || id >= b->nids) return NULL;
    return (const struct btf_type *)(b->types + b->idx[id]);
}
/* bytes of kind-specific trailing data after the 12-byte btf_type header */
static uint32_t btf_trailing(const struct btf_type *t) {
    switch (KIND(t)) {
    case KIND_INT: case KIND_VAR: case KIND_DECL_TAG: return 4;
    case KIND_ARRAY: return 12;
    case KIND_STRUCT: case KIND_UNION: return VLEN(t) * 12;
    case KIND_ENUM:      return VLEN(t) * 8;
    case KIND_ENUM64:    return VLEN(t) * 12;
    case KIND_FUNC_PROTO:return VLEN(t) * 8;
    case KIND_DATASEC:   return VLEN(t) * 12;
    default: return 0;
    }
}
/* build the id->offset index by walking the type section once, bounded by types_len */
static int btf_index(struct btf *b) {
    uint32_t cap = 1024, n = 1, off = 0;   /* id 0 reserved for void */
    b->idx = malloc(cap * sizeof(uint32_t));
    if (!b->idx) return -1;
    b->idx[0] = 0;
    while (off + sizeof(struct btf_type) <= b->types_len) {
        const struct btf_type *t = (const struct btf_type *)(b->types + off);
        uint32_t trail = btf_trailing(t);
        if (off + sizeof(struct btf_type) + trail > b->types_len) break;  /* truncated tail */
        if (n == cap) {
            uint32_t ncap = cap * 2;
            uint32_t *ni = realloc(b->idx, ncap * sizeof(uint32_t));
            if (!ni) return -1;
            b->idx = ni; cap = ncap;
        }
        b->idx[n++] = off;
        off += sizeof(struct btf_type) + trail;
    }
    b->nids = n;
    return 0;
}
int ls_core_btf_open(struct btf *b, const uint8_t *blob, uint32_t len) {
    memset(b, 0, sizeof *b);
    if (len < sizeof(struct btf_hdr)) return -1;
    uint16_t magic = rd16(blob);
    uint32_t hdr_len  = rd32(blob + 4);
    uint32_t type_off = rd32(blob + 8),  type_len = rd32(blob + 12);
    uint32_t str_off  = rd32(blob + 16), str_len  = rd32(blob + 20);
    if (magic != BTF_MAGIC) return -1;
    /* every span must lie wholly inside the blob (guard against overflow too) */
    if (hdr_len > len) return -1;
    if ((uint64_t)hdr_len + type_off + type_len > len) return -1;
    if ((uint64_t)hdr_len + str_off  + str_len  > len) return -1;
    b->types = blob + hdr_len + type_off; b->types_len = type_len;
    b->strs  = (const char *)(blob + hdr_len + str_off); b->strs_len = str_len;
    return btf_index(b);
}
void ls_core_btf_free(struct btf *b) { if (b && b->idx) { free(b->idx); b->idx = NULL; b->nids = 0; } }

/* Find the `.BTF` ELF section span, bounds-checked against elf_len. */
int ls_core_btf_find_in_elf(const uint8_t *elf, uint32_t elf_len,
                            const uint8_t **btf, uint32_t *btf_sz) {
    if (elf_len < 64) return -1;
    uint64_t shoff = rd64(elf + 0x28);
    uint16_t shentsize = rd16(elf + 0x3a), shnum = rd16(elf + 0x3c), shstrndx = rd16(elf + 0x3e);
    if (shentsize < 64 || shnum == 0 || shstrndx >= shnum) return -1;
    if (shoff > elf_len || (uint64_t)shnum * shentsize > elf_len - shoff) return -1;
    const uint8_t *she = elf + shoff + (uint64_t)shstrndx * shentsize;
    uint64_t str_off = rd64(she + 0x18), str_size = rd64(she + 0x20);
    if (str_off > elf_len || str_size > elf_len - str_off) return -1;
    const char *shstr = (const char *)(elf + str_off);
    for (uint16_t i = 0; i < shnum; i++) {
        const uint8_t *e = elf + shoff + (uint64_t)i * shentsize;
        uint32_t nameo = rd32(e);
        if (nameo >= str_size) continue;
        if (strcmp(shstr + nameo, ".BTF")) continue;   /* only the section we want --- do */
        uint64_t off = rd64(e + 0x18), sz = rd64(e + 0x20); /* NOT bounds-abort on NOBITS */
        if (off > elf_len || sz > elf_len - off) return -1; /* sections like .bss */
        *btf = elf + off; *btf_sz = (uint32_t)sz; return 0;
    }
    return -1;   /* no .BTF section */
}

/* skip const/volatile/restrict/typedef/type_tag qualifiers to the real type */
static const struct btf_type *btf_skip_mods(const struct btf *b, uint32_t *id) {
    const struct btf_type *t = btf_type_by_id(b, *id);
    int guard = 0;
    while (t && guard++ < 64) {
        int k = KIND(t);
        if (k==KIND_CONST||k==KIND_VOLATILE||k==KIND_RESTRICT||k==KIND_TYPEDEF||k==KIND_TYPE_TAG) {
            *id = t->size_or_type; t = btf_type_by_id(b, *id);
        } else break;
    }
    return t;
}
/* find a STRUCT/UNION of the given name in target BTF; returns id (0 = not found) */
static uint32_t btf_find_struct(const struct btf *b, const char *name) {
    for (uint32_t id = 1; id < b->nids; id++) {
        const struct btf_type *t = btf_type_by_id(b, id);
        int k = KIND(t);
        if ((k==KIND_STRUCT||k==KIND_UNION) && strcmp(btf_str(b,t->name_off),name)==0)
            return id;
    }
    return 0;
}
/* in target struct `st`, find member `name`; out: bit offset and member type id */
static int btf_find_member(const struct btf *b, const struct btf_type *st,
                           const char *name, uint32_t *bit_off, uint32_t *mtype) {
    const struct btf_member *m = (const struct btf_member *)(st + 1);
    for (uint32_t i = 0; i < VLEN(st); i++) {
        const char *mn = btf_str(b, m[i].name_off);
        if (mn[0] && strcmp(mn, name)==0) {
            uint32_t o = m[i].offset;
            *bit_off = KFLAG(st) ? (o & 0xffffff) : o;   /* bitfield-aware */
            *mtype = m[i].type;
            return 0;
        }
    }
    return -1;
}

/* Resolve one FIELD_BYTE_OFFSET relo.
 * local_id: type in the PROGRAM's BTF (gives per-level member NAMES).
 * access:   e.g. "0:2" --- arr[0] is the array index of the base, rest are member idxs.
 * Returns target byte offset, or -1 on any unsupported shape. */
static long core_field_offset(const struct btf *L, uint32_t local_id,
                              const char *access, const struct btf *T) {
    uint32_t acc[16]; int nacc = 0;
    for (const char *p = access; *p && nacc < 16; ) {
        acc[nacc++] = (uint32_t)strtoul(p, (char**)&p, 10);
        if (*p == ':') p++;
    }
    if (nacc < 1 || acc[0] != 0) return -1;   /* non-zero base array index: out of scope */

    uint32_t lid = local_id;
    const struct btf_type *lt = btf_skip_mods(L, &lid);
    if (!lt || (KIND(lt)!=KIND_STRUCT && KIND(lt)!=KIND_UNION)) return -1;

    const char *sname = btf_str(L, lt->name_off);
    if (!sname[0]) return -1;   /* anonymous root: out of scope */
    uint32_t tid = btf_find_struct(T, sname);
    if (!tid) return -1;
    const struct btf_type *tt = btf_type_by_id(T, tid);

    uint64_t bit_off = 0;
    for (int i = 1; i < nacc; i++) {
        uint32_t midx = acc[i];
        if (!lt || (KIND(lt)!=KIND_STRUCT && KIND(lt)!=KIND_UNION) || midx >= VLEN(lt)) return -1;
        if (!tt || (KIND(tt)!=KIND_STRUCT && KIND(tt)!=KIND_UNION)) return -1;
        const struct btf_member *lm = (const struct btf_member *)(lt + 1) + midx;
        const char *mname = btf_str(L, lm->name_off);
        uint32_t tbit, tmtype;
        if (btf_find_member(T, tt, mname, &tbit, &tmtype) < 0) return -1;
        bit_off += tbit;
        uint32_t nlid = lm->type; lt = btf_skip_mods(L, &nlid);
        uint32_t ntid = tmtype;   tt = btf_skip_mods(T, &ntid);
    }
    if (bit_off % 8) return -1;   /* sub-byte bitfield offset: not a byte offset */
    return (long)(bit_off / 8);
}

/* ---- the library entry point ---- */

/* Patch the s32 immediate (bytes 4..7) of the 8-byte insn at `insn_off` in the
 * program section, after bounds-checking.
 *
 * SCOPE BOUND (verified against docs.kernel.org/bpf/llvm_reloc.html, cached
 * kernel-llvm_reloc.html): a FIELD_BYTE_OFFSET relocation patches EITHER an
 * immediate (ALU/LD ops) OR an instruction's offset field (LDX/STX/ST). We patch
 * the IMMEDIATE only. That is correct for our programs because a verified program
 * cannot directly load `p->field` (PREVAIL refuses chasing the pointer); it must
 * use bpf_probe_read(&p->field), and `&p->field` compiles to an ALU add with the
 * offset as an immediate. The LDX/STX offset-field form does not arise for the
 * probe_read'd target fields we relocate. Supporting it would mean dispatching on
 * the insn opcode class here. */
static int patch_imm(uint8_t *sec, uint64_t sec_size, uint32_t insn_off, int32_t val) {
    if ((uint64_t)insn_off + 8 > sec_size) return -1;
    uint8_t *insn = sec + insn_off;
    insn[4] = (uint8_t)(val); insn[5] = (uint8_t)(val >> 8);
    insn[6] = (uint8_t)(val >> 16); insn[7] = (uint8_t)(val >> 24);
    return 0;
}

int ls_core_relocate(void *elf_v, uint32_t elf_len, const struct btf *target,
                     unsigned *n_out) {
    uint8_t *elf = elf_v;
    if (n_out) *n_out = 0;
    /* ELF64 header */
    if (elf_len < 64) return -LS_RELO_EBADELF;
    uint64_t shoff = rd64(elf + 0x28);
    uint16_t shentsize = rd16(elf + 0x3a), shnum = rd16(elf + 0x3c), shstrndx = rd16(elf + 0x3e);
    if (shentsize < 64 || shnum == 0 || shstrndx >= shnum) return -LS_RELO_EBADELF;
    if (shoff > elf_len || (uint64_t)shnum * shentsize > elf_len - shoff) return -LS_RELO_EBADELF;

    /* section-name string table */
    const uint8_t *she = elf + shoff + (uint64_t)shstrndx * shentsize;
    uint64_t shstr_off = rd64(she + 0x18), shstr_size = rd64(she + 0x20);
    if (shstr_off > elf_len || shstr_size > elf_len - shstr_off) return -LS_RELO_EBADELF;
    const char *shstr = (const char *)(elf + shstr_off);

    /* locate .BTF, .BTF.ext, and remember each section's data span */
    const uint8_t *btf_d = NULL, *ext_d = NULL; uint64_t btf_sz = 0, ext_sz = 0;
    for (uint16_t i = 0; i < shnum; i++) {
        const uint8_t *e = elf + shoff + (uint64_t)i * shentsize;
        uint32_t nameo = rd32(e);
        if (nameo >= shstr_size) continue;
        const char *nm = shstr + nameo;
        int isbtf = !strcmp(nm, ".BTF"), isext = !strcmp(nm, ".BTF.ext");
        if (!isbtf && !isext) continue;   /* skip; do NOT bounds-abort on NOBITS (.bss) */
        uint64_t off = rd64(e + 0x18), sz = rd64(e + 0x20);
        if (off > elf_len || sz > elf_len - off) return -LS_RELO_EBADELF;
        if (isbtf) { btf_d = elf + off; btf_sz = sz; } else { ext_d = elf + off; ext_sz = sz; }
    }
    if (!btf_d || !ext_d) return -LS_RELO_ENOBTF;

    struct btf L;
    if (btf_sz > 0xffffffffu || ls_core_btf_open(&L, btf_d, (uint32_t)btf_sz) < 0)
        return -LS_RELO_EBADBTF;

    /* .BTF.ext header: magic(2) ver(1) flags(1) hdr_len(4), then three (off,len) pairs;
     * core_relo is the third pair. */
    int rc = -LS_RELO_EBADBTF;
    if (ext_sz < 32) goto out;
    uint32_t hdr_len  = rd32(ext_d + 4);
    uint32_t core_off = rd32(ext_d + 24), core_len = rd32(ext_d + 28);
    if ((uint64_t)hdr_len + core_off + core_len > ext_sz || core_len < 4) goto out;
    const uint8_t *base = ext_d + hdr_len;
    const uint8_t *p    = base + core_off;
    const uint8_t *end  = p + core_len;
    uint32_t rec_size = rd32(p); p += 4;
    if (rec_size < 16) goto out;

    unsigned done = 0;
    while ((uint64_t)(end - p) >= 8) {
        uint32_t sec_name_off = rd32(p), num = rd32(p + 4); p += 8;
        const char *secname = btf_str(&L, sec_name_off);
        /* the program (code) section these relos apply to */
        uint8_t  *psec = NULL; uint64_t psec_sz = 0;
        for (uint16_t i = 0; i < shnum; i++) {
            const uint8_t *e = elf + shoff + (uint64_t)i * shentsize;
            uint32_t nameo = rd32(e);
            if (nameo < shstr_size && !strcmp(shstr + nameo, secname)) {
                uint64_t off = rd64(e + 0x18), sz = rd64(e + 0x20);
                if (off <= elf_len && sz <= elf_len - off) { psec = elf + off; psec_sz = sz; }
                break;
            }
        }
        for (uint32_t r = 0; r < num; r++) {
            if ((uint64_t)(end - p) < rec_size) { rc = -LS_RELO_EBADBTF; goto out; }
            uint32_t insn_off = rd32(p), type_id = rd32(p + 4),
                     acc_off  = rd32(p + 8), kind = rd32(p + 12);
            p += rec_size;
            if (kind != 0) { rc = -LS_RELO_EKIND; goto out; }      /* only FIELD_BYTE_OFFSET */
            long off = core_field_offset(&L, type_id, btf_str(&L, acc_off), target);
            if (off < 0) { rc = -LS_RELO_ENOFIELD; goto out; }
            if (!psec || patch_imm(psec, psec_sz, insn_off, (int32_t)off) < 0) {
                rc = -LS_RELO_EBOUNDS; goto out;
            }
            done++;
        }
    }
    if (n_out) *n_out = done;
    rc = LS_RELO_OK;
out:
    ls_core_btf_free(&L);
    return rc;
}

/* ---- self-test driver (not compiled into TMM) ----
 * Build:  gcc -O2 -Wall -DLS_CORE_RELO_TEST ls_core_relo.c -o relo
 * Run:    ./relo prog.o tmm.btf [out.o]   (exit 0 = every relo resolved)
 */
#ifdef LS_CORE_RELO_TEST
static int read_file(const char *path, uint8_t **buf, size_t *len) {
    FILE *f = fopen(path,"rb"); if(!f) return -1;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    *buf=malloc(n); *len=fread(*buf,1,n,f); fclose(f); return 0;
}
int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr,"usage: %s prog.o tmm.btf [out.o]\n",argv[0]); return 2; }
    uint8_t *elf; size_t elflen; if (read_file(argv[1],&elf,&elflen)) return 2;
    uint8_t *tbtf; size_t tbtflen; if (read_file(argv[2],&tbtf,&tbtflen)) return 2;
    struct btf T;
    if (ls_core_btf_open(&T, tbtf, (uint32_t)tbtflen) < 0) { fprintf(stderr,"bad target BTF\n"); return 2; }
    fprintf(stderr,"target BTF: %u types\n", T.nids-1);
    unsigned n = 0;
    int rc = ls_core_relocate(elf, (uint32_t)elflen, &T, &n);
    fprintf(stderr,"ls_core_relocate rc=%d, %u relo(s)\n", rc, n);
    if (rc == LS_RELO_OK && argc >= 4) {
        FILE *o = fopen(argv[3],"wb");
        if (o) { fwrite(elf,1,elflen,o); fclose(o); fprintf(stderr,"wrote relocated object: %s\n", argv[3]); }
    }
    ls_core_btf_free(&T);
    return rc == LS_RELO_OK ? 0 : 1;
}
#endif /* LS_CORE_RELO_TEST */
