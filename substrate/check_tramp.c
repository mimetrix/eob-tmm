#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define LS_SAFE_RETURN 1
static int g_verdict; static uint64_t g_seen[5];
int ls_vm_call(int slot,void*ctx,size_t n){(void)slot;memcpy(g_seen,ctx,n<sizeof g_seen?n:sizeof g_seen);return g_verdict;}
extern uint64_t victim(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t body_ran;
int main(void){
    int f=0;
    g_verdict=0; body_ran=0; memset(g_seen,0,sizeof g_seen);
    uint64_t r=victim(0xA1,0xB2,0xC3,0xD4,0xE5);
    printf("  FALLTHROUGH: ret=%#llx body_ran=%llu  args seen=%#llx %#llx %#llx %#llx %#llx\n",
        (unsigned long long)r,(unsigned long long)body_ran,
        (unsigned long long)g_seen[0],(unsigned long long)g_seen[1],(unsigned long long)g_seen[2],
        (unsigned long long)g_seen[3],(unsigned long long)g_seen[4]);
    if(r!=0xBEEF||body_ran!=1){puts("  FAIL body did not run");f++;}else puts("  ok   body ran, correct return");
    if(g_seen[0]!=0xA1||g_seen[4]!=0xE5){puts("  FAIL arg capture");f++;}else puts("  ok   args captured before the prologue");

    g_verdict=LS_SAFE_RETURN; body_ran=0;
    r=victim(1,2,3,4,5);
    printf("  SAFE_RETURN: ret=%#llx body_ran=%llu\n",(unsigned long long)r,(unsigned long long)body_ran);
    if(body_ran!=0){puts("  FAIL body ran despite safe return");f++;}else puts("  ok   body SKIPPED");
    if(r!=0){puts("  FAIL safe value");f++;}else puts("  ok   safe value delivered to caller");
    printf("\n  %s\n", f?"FAILURES":"trampoline validated end to end");
    return f;
}
