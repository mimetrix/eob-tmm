/* Controlled native source for reader handoff and failure tests. No TMM code. */
#include <inttypes.h>
#include <stdlib.h>
#include "../ls_tp_ring.h"

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    struct ls_tp_seg *s = ls_tp_seg_open(argv[1], 1);
    if (!s) return 3;
    struct ls_ring *r = ls_tp_my_ring(s);
    uint64_t sequence = 0;
    char command[4096] = {0};
    printf("{\"ready\":true}\n");
    fflush(stdout);
    while (fgets(command, sizeof command, stdin)) {
        unsigned count = 0;
        char hex[1025] = {0};
        unsigned emitted = 0;
        int consumed = -1;
        if (sscanf(command, "emit %u %1024s", &count, hex) == 2) {
            unsigned len = (unsigned)strlen(hex) / 2;
            unsigned char data[512] = {0};
            if (count > 100000 || strlen(hex) != 2 * len) return 4;
            for (unsigned i = 0; i < len; i++) {
                unsigned byte = 0;
                if (sscanf(hex + 2 * i, "%2x", &byte) != 1) return 5;
                data[i] = (unsigned char)byte;
            }
            for (unsigned i = 0; i < count; i++) {
                struct ls_rec rec = {.hook_id = 100, .schema_id = 100,
                    .seq = ++sequence, .slot = 7, .len = len, .ts_ns = sequence};
                emitted += ls_ring_emit(r, &rec, data, len);
            }
        } else if (!strcmp(command, "consume\n")) {
            struct ls_rec rec = {0};
            unsigned char data[512] = {0};
            consumed = ls_ring_consume(r, &rec, data, sizeof data);
            /* No payload output or downstream acceptance before this status. */
        } else if (!strcmp(command, "corrupt\n")) {
            s->version = 99;
        } else if (!strcmp(command, "misalign\n")) {
            atomic_store(&r->consumer_pos, 1);
        } else if (!strcmp(command, "quit\n")) {
            break;
        } else if (strcmp(command, "status\n")) {
            return 6;
        }
        printf("{\"producer\":\"%" PRIu64 "\",\"consumer\":\"%" PRIu64
               "\",\"drops\":\"%" PRIu64 "\",\"emitted\":%u,\"consumed\":%d}\n",
               atomic_load(&r->producer_pos), atomic_load(&r->consumer_pos),
               atomic_load(&r->drops), emitted, consumed);
        fflush(stdout);
    }
    munmap(s, LS_TP_SEG_SZ);
    return 0;
}
