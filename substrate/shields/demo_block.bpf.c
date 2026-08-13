/* returns SAFE_RETURN (1): the hooked body should be skipped */
__attribute__((section("fentry/demo_block"), used))
unsigned long long shield(void *ctx){ (void)ctx; return 1; }
