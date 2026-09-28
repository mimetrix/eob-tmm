/* Exercise the runtime parser/check against independently produced ELF files. */
#include "ls_target.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 5) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f || fseek(f, 0, SEEK_END)) return 2;
    long size = ftell(f);
    if (size < 0 || size > 1048576 || fseek(f, 0, SEEK_SET)) return 2;
    void *blob = malloc((size_t)size + 1);
    if (!blob || fread(blob, 1, (size_t)size, f) != (size_t)size) return 2;
    fclose(f);
    struct ls_target target;
    int rc = ls_target_parse(blob, (size_t)size, argv[2], argv[3], &target);
    free(blob);
    if (rc) return 1;
    if (ls_target_check_file(argv[4], &target)) return 1;
    printf("PASS target=0x%llx kind=%u pad=%u\n",
           (unsigned long long)target.entry, target.is_exit, target.pad_offset);
    return 0;
}
