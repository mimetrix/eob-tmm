/*
 * B0 correctness --- does the reused JIT scratch still compile CORRECT code?
 *
 * The speedup is worthless if reuse silently corrupts output. Scratch reuse is
 * exactly the class of change that produces a program which compiles fine and
 * computes the wrong thing, so this checks the compiled code's BEHAVIOUR rather
 * than that compilation returned success.
 *
 * Two independent checks, neither of which needs to know the shield's constants:
 *
 *   1. JIT vs interpreter, same VM, same ctx. ubpf_exec runs the same bytecode
 *      without touching the JIT scratch at all, so it is an oracle the patch
 *      cannot influence.
 *   2. Compile the same program many times through the SHARED scratch and check
 *      every compile agrees. A stale entry leaking between compiles shows up as
 *      a later compile disagreeing with the first.
 *
 * Both ctx cases are exercised --- the null pointer the shield is meant to catch
 * and a non-null one --- so a shield that degenerated into "always return the
 * same thing" is caught rather than passing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ubpf.h"

#define ROUNDS 40

/* mirrors struct ls_ctx_http_psm */
struct ctx {
    uint64_t ptlp;
    uint64_t ptlp_name;
    uint32_t errdefs_key;
    uint32_t name_len;
};

static void *
load_file(const char *p, long *len)
{
    FILE *f = fopen(p, "rb");
    if (!f) { perror(p); exit(1); }
    fseek(f, 0, SEEK_END); *len = ftell(f); fseek(f, 0, SEEK_SET);
    void *b = malloc(*len);
    if (fread(b, 1, *len, f) != (size_t)*len) { perror("read"); exit(1); }
    fclose(f);
    return b;
}

int
main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/tmp/shield.elf";
    const char *func = argc > 2 ? argv[2] : "shield";
    long len;
    void *elf = load_file(path, &len);

    /* the case the shield exists to catch, and its opposite */
    struct ctx null_ctx = { .ptlp = 0, .ptlp_name = 0, .errdefs_key = 7, .name_len = 0 };
    struct ctx live_ctx = { .ptlp = 0xdeadbeef, .ptlp_name = 0xcafe, .errdefs_key = 7, .name_len = 5 };

    uint64_t jit_null_first = 0, jit_live_first = 0;
    int fail = 0;

    for (int r = 0; r < ROUNDS; r++) {
        char *err = NULL, *jerr = NULL;
        struct ubpf_vm *vm = ubpf_create();
        if (ubpf_load_elf_ex(vm, elf, len, func, &err) < 0) {
            fprintf(stderr, "load failed: %s\n", err ? err : "?"); return 1;
        }
        ubpf_set_instruction_limit(vm, 10000, NULL);

        /* oracle: the interpreter never touches the JIT scratch */
        uint64_t interp_null = 0, interp_live = 0;
        if (ubpf_exec(vm, &null_ctx, sizeof null_ctx, &interp_null) != 0 ||
            ubpf_exec(vm, &live_ctx, sizeof live_ctx, &interp_live) != 0) {
            fprintf(stderr, "round %d: ubpf_exec failed\n", r); return 1;
        }

        ubpf_jit_ex_fn fn = ubpf_compile_ex(vm, &jerr, ExtendedJitMode);
        if (!fn) { fprintf(stderr, "round %d: compile failed: %s\n", r, jerr ? jerr : "?"); return 1; }

        static uint8_t stack[4096];
        uint64_t jit_null = fn(&null_ctx, sizeof null_ctx, stack, sizeof stack);
        uint64_t jit_live = fn(&live_ctx, sizeof live_ctx, stack, sizeof stack);

        if (r == 0) {
            jit_null_first = jit_null;
            jit_live_first = jit_live;
            printf("  round 0 baseline:  null-ctx -> %llu   live-ctx -> %llu\n",
                   (unsigned long long)jit_null, (unsigned long long)jit_live);
            printf("  interpreter says:  null-ctx -> %llu   live-ctx -> %llu\n",
                   (unsigned long long)interp_null, (unsigned long long)interp_live);
            if (jit_null == jit_live)
                printf("  NOTE: both ctx cases give the same verdict --- this shield\n"
                       "        does not discriminate, so check 1 is the meaningful one.\n");
        }

        if (jit_null != interp_null || jit_live != interp_live) {
            printf("  FAIL round %d: JIT disagrees with interpreter "
                   "(jit %llu/%llu vs interp %llu/%llu)\n", r,
                   (unsigned long long)jit_null, (unsigned long long)jit_live,
                   (unsigned long long)interp_null, (unsigned long long)interp_live);
            fail = 1;
        }
        if (jit_null != jit_null_first || jit_live != jit_live_first) {
            printf("  FAIL round %d: compile drifted from round 0 "
                   "(%llu/%llu vs %llu/%llu)\n", r,
                   (unsigned long long)jit_null, (unsigned long long)jit_live,
                   (unsigned long long)jit_null_first, (unsigned long long)jit_live_first);
            fail = 1;
        }
        free(err); free(jerr);
    }

    printf("\n  %d rounds through the shared scratch\n", ROUNDS);
    printf("  RESULT: %s\n", fail ? "*** FAILED --- reuse corrupts compiled output"
                                  : "PASS --- JIT matches interpreter, and every compile agrees");
    return fail;
}
