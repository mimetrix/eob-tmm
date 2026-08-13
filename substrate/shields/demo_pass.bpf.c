/* returns FALLTHROUGH (0): the hooked body should run */
__attribute__((section("fentry/demo_pass"), used))
unsigned long long shield(void *ctx){ (void)ctx; return 0; }
