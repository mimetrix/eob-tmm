/* check_alpn_get.c --- executes ls_h_alpn.c's logic against a stubbed accessor. Asserts fault
 * safety and the header skip, so the helper is verified rather than merely written. */
#define LS_ALPN_TEST 1
#include "ls_h_alpn.c"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int   g_stub_rc; BYTE *g_stub_ext; SIZE g_stub_len;
#define BAD ((uint64_t)-1)

int main(void)
{
    BYTE dst[64];
    /* a synthetic ALPN extension: 4-byte header + 2-byte list-len + entry list "\x02h2\x08http/1.1" */
    BYTE ext[6 + 3 + 9];
    memset(ext, 0, sizeof ext);
    ext[6] = 2; ext[7]='h'; ext[8]='2';
    ext[9] = 8; memcpy(&ext[10], "http/1.1", 8);
    SIZE entry_len = 3 + 9;                 /* what the program should receive */

    int f = 0;
    /* refusals */
    if (ls_h_alpn_get(0, 64, 1, 0, 0) != BAD) { puts("FAIL null dst"); f++; }
    if (ls_h_alpn_get((uint64_t)(uintptr_t)dst, 0, 1, 0, 0) != BAD) { puts("FAIL zero len"); f++; }
    if (ls_h_alpn_get((uint64_t)(uintptr_t)dst, 65, 1, 0, 0) != BAD) { puts("FAIL over-cap len"); f++; }
    if (ls_h_alpn_get((uint64_t)(uintptr_t)dst, 64, 0, 0, 0) != BAD) { puts("FAIL null sc"); f++; }
    g_stub_rc = 1;                          /* accessor says not-OK */
    if (ls_h_alpn_get((uint64_t)(uintptr_t)dst, 64, 1, 0, 0) != BAD) { puts("FAIL accessor err"); f++; }
    g_stub_rc = ERR_OK; g_stub_ext = ext; g_stub_len = 5;   /* too short to hold a list */
    if (ls_h_alpn_get((uint64_t)(uintptr_t)dst, 64, 1, 0, 0) != BAD) { puts("FAIL too short"); f++; }
    g_stub_ext = 0; g_stub_len = sizeof ext;                /* null ext */
    if (ls_h_alpn_get((uint64_t)(uintptr_t)dst, 64, 1, 0, 0) != BAD) { puts("FAIL null ext"); f++; }

    /* success: skips the 6-byte header, returns the entry-list, bounded */
    memset(dst, 0xAA, sizeof dst);
    g_stub_rc = ERR_OK; g_stub_ext = ext; g_stub_len = sizeof ext;
    uint64_t r = ls_h_alpn_get((uint64_t)(uintptr_t)dst, 64, 1, 0, 0);
    if (r != entry_len) { printf("FAIL len: got %llu want %lu\n", (unsigned long long)r, entry_len); f++; }
    else if (dst[0] != 2 || dst[1] != 'h' || dst[2] != '2' || dst[3] != 8) { puts("FAIL skip/copy"); f++; }
    else puts("ok    header skipped, entry list copied, length returned");

    /* bounded: a huge extension is truncated to the program's buffer, never past it */
    g_stub_len = 6 + 200;                   /* claims 200 bytes of entries */
    r = ls_h_alpn_get((uint64_t)(uintptr_t)dst, 64, 1, 0, 0);
    if (r != 64) { printf("FAIL bound: got %llu want 64\n", (unsigned long long)r); f++; }
    else puts("ok    over-long list bounded to the buffer");

    printf("\n  %s\n", f ? "FAILURES" : "ls_h_alpn_get: all assertions pass");
    return f;
}
