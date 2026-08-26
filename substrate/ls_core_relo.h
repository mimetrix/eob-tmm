/* ls_core_relo.h --- CO-RE field-offset relocation for the loader.
 *
 * A portable program (surface/shield) names TMM fields by struct+field NAME and
 * carries .BTF + .BTF.ext relocation records. At load, ls_core_relocate() resolves
 * each field's byte offset against THIS build's BTF and patches the instruction
 * immediate --- so one bytecode runs on any build, no baked offsets, no rebuild.
 *
 * Scope: kind=0 FIELD_BYTE_OFFSET, the only kind our compiler emits for
 * preserve_access_index field reads. Every other kind is rejected (fail-dark).
 *
 * Runs on the TMM thread (via ls_prep_run_pending -> ls_vm_reload), where malloc
 * is legal; it is NOT safe on the loader pthread.
 */
#ifndef LS_CORE_RELO_H
#define LS_CORE_RELO_H

#include <stdint.h>

/* Parsed BTF: a type-id -> byte-offset index over an in-memory BTF blob.
 * The blob must outlive the struct (not copied). Free idx with free(). */
struct btf {
    const uint8_t *types;  uint32_t types_len;
    const char    *strs;   uint32_t strs_len;
    uint32_t      *idx;    uint32_t nids;   /* idx[id] = byte offset in types[] */
};

/* Parse a BTF blob (the target build's BTF, or a program's local .BTF) into `b`.
 * Returns 0 on success, <0 on a malformed blob. Allocates b->idx (free() it). */
int ls_core_btf_open(struct btf *b, const uint8_t *blob, uint32_t len);
void ls_core_btf_free(struct btf *b);

/* Relocate `elf` (an eBPF program object, MUTABLE) in place against `target`.
 * Parses the program's own .BTF/.BTF.ext, resolves every FIELD_BYTE_OFFSET record
 * by field name against `target`, and patches the instruction immediates.
 * Returns 0 iff EVERY record resolved and was patched; <0 (and leaves the object
 * untrusted) if the object is malformed, carries an unsupported record kind, or a
 * field is absent in the target --- the caller MUST refuse to load on <0.
 * n_out (optional) receives the number of records relocated. */
int ls_core_relocate(void *elf, uint32_t elf_len, const struct btf *target,
                     unsigned *n_out);

/* relocation result codes (negated on return) */
enum {
    LS_RELO_OK            = 0,
    LS_RELO_EBADELF       = 1,   /* ELF header/section table out of bounds        */
    LS_RELO_ENOBTF        = 2,   /* program lacks .BTF/.BTF.ext                    */
    LS_RELO_EBADBTF       = 3,   /* malformed local BTF or .BTF.ext               */
    LS_RELO_EKIND         = 4,   /* unsupported relocation kind                   */
    LS_RELO_ENOFIELD      = 5,   /* field/struct absent in target, or bitfield    */
    LS_RELO_EBOUNDS       = 6,   /* insn offset outside its program section       */
};

#endif /* LS_CORE_RELO_H */
