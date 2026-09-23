/* Live regression for CONTESTED-PREMISES.md §17. Compile twice:
 *   -DKIND='"fentry/http_parse_client_headers"' -DFIRST=5
 *   -DKIND='"fexit/http_parse_client_headers"'  -DFIRST=6
 * Verify, admit fexit against the packaged binary, then sign for that build with
 * a MONITOR ceiling. Run only on a binary containing the 96-byte allocation fix.
 *
 * A verdict of 1 means every reserved word was zero on arrival. Poison every
 * reserved word afterwards, including bytes 88..95: the next invocation must
 * still see zeros. Volatile keeps all reads/writes in the emitted bytecode.
 * Arguments and the exit return value are left intact. Monitor mode counts the
 * verdict but does not apply SAFE_RETURN. This is a contract test, not a shield.
 * Literal bounds deliberately do not depend on the runtime's size constant.
 */
#if FIRST != 5 && FIRST != 6
#error FIRST must be 5 (entry) or 6 (exit)
#endif

__attribute__((section(KIND), used))
unsigned long long check_ctx_live(volatile unsigned long long *ctx)
{
    unsigned long long nonzero = 0;
#pragma unroll
    for (int i = FIRST; i < 12; ++i)
        nonzero |= ctx[i];
#pragma unroll
    for (int i = FIRST; i < 12; ++i)
        ctx[i] = 0x6374783936746169ull;
    return nonzero == 0;
}
