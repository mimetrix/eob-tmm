/* Separate translation unit: the caller must observe the patched return value,
 * not a value inferred from the original function body by the compiler. */
#include <stdint.h>
extern unsigned bodies;
__attribute__((noinline, patchable_function_entry(5, 0)))
uint64_t program_alpha(uint64_t a, uint64_t b) { bodies++; return a + b; }
__attribute__((noinline, patchable_function_entry(5, 0)))
uint64_t program_beta(uint64_t a, uint64_t b) { bodies++; return a + b + 10; }

#define EXTRA(n) \
    __attribute__((noinline, patchable_function_entry(5, 0))) \
    uint64_t program_extra##n(uint64_t a, uint64_t b) { bodies++; return a + b + n; }
EXTRA(0) EXTRA(1) EXTRA(2) EXTRA(3) EXTRA(4) EXTRA(5) EXTRA(6)
EXTRA(7) EXTRA(8) EXTRA(9) EXTRA(10) EXTRA(11) EXTRA(12) EXTRA(13)
