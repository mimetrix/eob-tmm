/*
 * B1 --- how long does preparing a shield actually take?
 *
 * The load-path fix (load-path-scope.md) moves ubpf_create/load/compile onto a
 * TMM poll thread, where umalloc works. That trades a hung loader for a stalled
 * poll iteration, and the trade is only acceptable if the stall is small. This
 * measures it before any of that gets written.
 *
 * Mirrors ls_vm.c:484-522 exactly --- same call sequence, same ExtendedJitMode,
 * same instruction limit --- so the number means something for the real path:
 *
 *     ubpf_create()
 *     ubpf_load_elf_ex(vm, elf, len, function, &err)
 *     ubpf_set_instruction_limit(vm, 10000, NULL)
 *     ubpf_compile_ex(vm, &err, ExtendedJitMode)
 *
 * Reports each stage separately. create+load is the part that would move; the
 * JIT is expected to dominate because ubpf_jit_support.c callocs five arrays of
 * UBPF_MAX_INSTS=65536 on every compile regardless of program size.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ubpf.h"

#define ITERS 50

static double
now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int
cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void
report(const char *label, double *v, int n)
{
    qsort(v, n, sizeof v[0], cmp_double);
    double sum = 0;
    for (int i = 0; i < n; i++)
        sum += v[i];
    printf("  %-22s min %8.1f us   median %8.1f us   p95 %8.1f us   max %8.1f us   mean %8.1f us\n",
           label, v[0], v[n / 2], v[(int)(n * 0.95)], v[n - 1], sum / n);
}

int
main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/tmp/shield.elf";
    const char *func = argc > 2 ? argv[2] : "shield";

    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *elf = malloc(len);
    if (fread(elf, 1, len, f) != (size_t)len) { perror("read"); return 1; }
    fclose(f);

    printf("program: %s  (%ld bytes)  function=%s  iters=%d\n\n", path, len, func, ITERS);

    double t_create[ITERS], t_load[ITERS], t_jit[ITERS], t_total[ITERS];
    int ok = 0;

    for (int i = 0; i < ITERS; i++) {
        char *err = NULL, *jerr = NULL;
        double a = now_us();

        struct ubpf_vm *vm = ubpf_create();
        double b = now_us();
        if (!vm) { fprintf(stderr, "ubpf_create failed\n"); return 1; }

        if (ubpf_load_elf_ex(vm, elf, len, func, &err) < 0) {
            fprintf(stderr, "load failed: %s\n", err ? err : "?");
            return 1;
        }
        double c = now_us();

        ubpf_set_instruction_limit(vm, 10000, NULL);

        ubpf_jit_fn fn = ubpf_compile_ex(vm, &jerr, ExtendedJitMode);
        double d = now_us();
        if (!fn) {
            fprintf(stderr, "compile failed: %s\n", jerr ? jerr : "?");
            return 1;
        }
        ok++;

        t_create[i] = b - a;
        t_load[i]   = c - b;
        t_jit[i]    = d - c;
        t_total[i]  = d - a;

        /* NOTE: not destroying the VM. ubpf_destroy would skew the timing and
         * the real path leaks it too --- reclamation is item 0c, unwritten. */
        free(err); free(jerr);
    }

    printf("  %d/%d compiled OK\n\n", ok, ITERS);
    report("ubpf_create",        t_create, ITERS);
    report("ubpf_load_elf_ex",   t_load,   ITERS);
    report("ubpf_compile_ex",    t_jit,    ITERS);
    report("TOTAL (the stall)",  t_total,  ITERS);

    qsort(t_total, ITERS, sizeof t_total[0], cmp_double);
    double med = t_total[ITERS / 2];
    printf("\n  VERDICT vs a poll iteration:\n");
    printf("    median total = %.0f us = %.3f ms\n", med, med / 1000.0);
    if (med < 100)
        printf("    -> under 100 us. Comparable to other per-iteration work; the trade is fine.\n");
    else if (med < 1000)
        printf("    -> 100 us - 1 ms. Noticeable stall; acceptable only because loads are rare.\n");
    else
        printf("    -> OVER 1 ms. Too long to sit inside a poll iteration. The design must change.\n");
    return 0;
}
