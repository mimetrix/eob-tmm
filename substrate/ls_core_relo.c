/* ls_core_relo.c --- CO-RE field-offset relocation, no libbpf/kernel deps.
 *
 * Scope (Phase 3): the exact subset our compiler emits for preserve_access_index
 * field reads --- kind=0 FIELD_BYTE_OFFSET. Reads .BTF.ext CO-RE records from the
 * program object, resolves each field's byte offset against TMM's BTF (by field
 * NAME, per level), and patches the instruction immediate. Everything else is
 * rejected loudly, not silently mis-relocated.
 *
 * BTF and .BTF.ext binary layout per kernel Documentation/bpf/btf.rst.
 */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

struct btf {
    const uint8_t *types;  uint32_t types_len;
    const char    *strs;   uint32_t strs_len;
    /* id -> byte offset within types[] (id is 1-based; id 0 == void) */
    uint32_t *idx;  uint32_t nids;
};

#define KIND(t)      (((t)->info >> 24) & 0x1f)
#define VLEN(t)      ((t)->info & 0xffff)
#define KFLAG(t)     (((t)->info >> 31) & 1)

static const char *btf_str(const struct btf *b, uint32_t off) {
    return off < b->strs_len ? b->strs + off : "(bad)";
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
/* build the id->offset index by walking the type section once */
static int btf_index(struct btf *b) {
    uint32_t cap = 1024, n = 1, off = 0;   /* id 0 reserved for void */
    b->idx = malloc(cap * sizeof(uint32_t));
    if (!b->idx) return -1;
    b->idx[0] = 0;
    while (off + sizeof(struct btf_type) <= b->types_len) {
        const struct btf_type *t = (const struct btf_type *)(b->types + off);
        if (n == cap) { cap *= 2; b->idx = realloc(b->idx, cap*sizeof(uint32_t));
                        if (!b->idx) return -1; }
        b->idx[n++] = off;
        off += sizeof(struct btf_type) + btf_trailing(t);
    }
    b->nids = n;
    return 0;
}
static int btf_open(struct btf *b, const uint8_t *blob, uint32_t len) {
    if (len < sizeof(struct btf_hdr)) return -1;
    const struct btf_hdr *h = (const struct btf_hdr *)blob;
    if (h->magic != BTF_MAGIC) { fprintf(stderr,"bad BTF magic 0x%x\n",h->magic); return -1; }
    b->types = blob + h->hdr_len + h->type_off; b->types_len = h->type_len;
    b->strs  = (const char *)(blob + h->hdr_len + h->str_off); b->strs_len = h->str_len;
    return btf_index(b);
}
/* skip const/volatile/restrict/typedef/type_tag qualifiers to the real type */
static const struct btf_type *btf_skip_mods(const struct btf *b, uint32_t *id) {
    const struct btf_type *t = btf_type_by_id(b, *id);
    while (t) {
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
        /* anonymous member: could recurse; our structs don't need it (rejected below) */
    }
    return -1;
}

/* Resolve one FIELD_BYTE_OFFSET relo.
 * local_id: type in the PROGRAM's BTF (gives per-level member NAMES).
 * access:   e.g. "0:2" --- arr[0] is the array index of the base, rest are member idxs.
 * Returns target byte offset, or -1 on any unsupported shape. */
static long core_field_offset(const struct btf *L, uint32_t local_id,
                              const char *access, const struct btf *T) {
    /* parse access spec */
    uint32_t acc[16]; int nacc = 0;
    for (const char *p = access; *p && nacc < 16; ) {
        acc[nacc++] = (uint32_t)strtoul(p, (char**)&p, 10);
        if (*p == ':') p++;
    }
    if (nacc < 1) return -1;
    if (acc[0] != 0) return -1;   /* non-zero base array index: out of scope */

    uint32_t lid = local_id;
    const struct btf_type *lt = btf_skip_mods(L, &lid);
    if (!lt || (KIND(lt)!=KIND_STRUCT && KIND(lt)!=KIND_UNION)) return -1;

    /* find the matching struct by name in the target */
    const char *sname = btf_str(L, lt->name_off);
    if (!sname[0]) return -1;   /* anonymous root: out of scope */
    uint32_t tid = btf_find_struct(T, sname);
    if (!tid) { fprintf(stderr,"  target has no struct '%s'\n", sname); return -1; }
    const struct btf_type *tt = btf_type_by_id(T, tid);

    uint64_t bit_off = 0;
    for (int i = 1; i < nacc; i++) {
        uint32_t midx = acc[i];
        if (midx >= VLEN(lt)) return -1;
        const struct btf_member *lm = (const struct btf_member *)(lt + 1) + midx;
        const char *mname = btf_str(L, lm->name_off);
        uint32_t tbit, tmtype;
        if (btf_find_member(T, tt, mname, &tbit, &tmtype) < 0) {
            fprintf(stderr,"  target struct missing member '%s'\n", mname); return -1;
        }
        bit_off += tbit;
        /* descend for the next level */
        uint32_t nlid = lm->type; lt = btf_skip_mods(L, &nlid);
        uint32_t ntid = tmtype;   tt = btf_skip_mods(T, &ntid);
    }
    if (bit_off % 8) { fprintf(stderr,"  bitfield field offset unsupported\n"); return -1; }
    return (long)(bit_off / 8);
}

/* ---- ELF + .BTF.ext walk (self-test driver) ----
 * Build the test:  gcc -O2 -Wall -DLS_CORE_RELO_TEST ls_core_relo.c -o relo
 * Run:             ./relo prog.o tmm.btf   (exit 0 = all relos resolved)
 * Library only:    gcc -c ls_core_relo.c   (no main; for linking into the loader)
 */
#ifdef LS_CORE_RELO_TEST
struct sec { const char *name; const uint8_t *data; uint64_t size; };
static int read_file(const char *path, uint8_t **buf, size_t *len) {
    FILE *f = fopen(path,"rb"); if(!f) return -1;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    *buf=malloc(n); *len=fread(*buf,1,n,f); fclose(f); return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr,"usage: %s prog.o tmm.btf\n",argv[0]); return 2; }
    uint8_t *elf; size_t elflen; if (read_file(argv[1],&elf,&elflen)) return 2;
    uint8_t *tbtf; size_t tbtflen; if (read_file(argv[2],&tbtf,&tbtflen)) return 2;

    /* ELF64 section table */
    uint64_t shoff = *(uint64_t*)(elf+0x28);
    uint16_t shentsize=*(uint16_t*)(elf+0x3a), shnum=*(uint16_t*)(elf+0x3c), shstrndx=*(uint16_t*)(elf+0x3e);
    const uint8_t *sh = elf+shoff;
    uint64_t shstr_off = *(uint64_t*)(sh+shstrndx*shentsize+0x18);
    struct sec S[64]; int ns=0;
    for (int i=0;i<shnum && ns<64;i++){ const uint8_t *e=sh+i*shentsize;
        uint32_t nameo=*(uint32_t*)e; uint64_t off=*(uint64_t*)(e+0x18), sz=*(uint64_t*)(e+0x20);
        S[ns].name=(const char*)(elf+shstr_off+nameo); S[ns].data=elf+off; S[ns].size=sz; ns++; }
    const struct sec *btf=NULL,*ext=NULL;
    for(int i=0;i<ns;i++){ if(!strcmp(S[i].name,".BTF"))btf=&S[i]; if(!strcmp(S[i].name,".BTF.ext"))ext=&S[i]; }
    if(!btf||!ext){fprintf(stderr,"missing .BTF/.BTF.ext\n");return 2;}

    struct btf L={0}, T={0};
    if (btf_open(&L, btf->data, btf->size)) return 2;
    if (btf_open(&T, tbtf, tbtflen)) return 2;
    fprintf(stderr,"local BTF: %u types  |  TMM BTF: %u types\n", L.nids-1, T.nids-1);

    /* .BTF.ext header -> core_relo */
    const uint8_t *d=ext->data;
    uint32_t hdr_len=*(uint32_t*)(d+4);
    uint32_t core_off=*(uint32_t*)(d+24), core_len=*(uint32_t*)(d+28);
    const uint8_t *base=d+hdr_len;
    const uint8_t *p=base+core_off;
    uint32_t rec_size=*(uint32_t*)p; p+=4;
    const uint8_t *end=base+core_off+core_len;
    int fails=0, total=0;
    while (p < end) {
        uint32_t sec_name_off=*(uint32_t*)p, num=*(uint32_t*)(p+4); p+=8;
        const char *secname = btf_str(&L, sec_name_off);
        for (uint32_t r=0;r<num;r++){
            uint32_t insn_off=*(uint32_t*)p, type_id=*(uint32_t*)(p+4),
                     acc_off=*(uint32_t*)(p+8), kind=*(uint32_t*)(p+12);
            p+=rec_size;
            const char *acc=btf_str(&L,acc_off);
            total++;
            if (kind != 0) { fprintf(stderr,"[%s] insn@%u UNSUPPORTED kind=%u --- rejected\n",secname,insn_off,kind); fails++; continue; }
            long off = core_field_offset(&L, type_id, acc, &T);
            if (off < 0) { fprintf(stderr,"[%s] insn@%u access='%s' --- RELOC FAILED\n",secname,insn_off,acc); fails++; continue; }
            long loc = core_field_offset(&L, type_id, acc, &L);
            /* patch: find the program section by name, rewrite the insn imm (bytes 4..7) */
            const struct sec *ps=NULL; for(int i=0;i<ns;i++) if(!strcmp(S[i].name,secname)) ps=&S[i];
            int32_t imm_before=0, imm_after=0;
            if (ps && insn_off+8 <= ps->size) {
                uint8_t *insn = (uint8_t*)ps->data + insn_off;   /* driver: patch in place */
                memcpy(&imm_before, insn+4, 4);
                int32_t v=(int32_t)off; memcpy(insn+4, &v, 4);
                memcpy(&imm_after, insn+4, 4);
            }
            printf("[%s] insn#%u (byte %u) type_id=%u access='%s'  local_off=%ld -> TMM_off=%ld   imm: %d -> %d\n",
                   secname, insn_off/8, insn_off, type_id, acc, loc, off, imm_before, imm_after);
        }
    }
    fprintf(stderr,"\n%d relo(s), %d failed\n", total, fails);
    if (argc >= 4 && !fails) {   /* write the relocated object (patches applied in place) */
        FILE *o = fopen(argv[3],"wb");
        if (o) { fwrite(elf,1,elflen,o); fclose(o); fprintf(stderr,"wrote relocated object: %s\n", argv[3]); }
    }
    return fails ? 1 : 0;
}
#endif /* LS_CORE_RELO_TEST */
