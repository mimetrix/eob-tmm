/* Verifier half of the context contract. INDEX=11 reads bytes 88..95;
 * INDEX=12 reads 96..103 and must be refused. Compile for both tracing hooks.
 * Deliberately independent of the runtime's size constant: verifier drift must
 * fail this test, not silently move both sides of it together.
 */
__attribute__((section(KIND), used))
unsigned long long shield(const unsigned long long *ctx)
{
    return ctx[INDEX];
}
