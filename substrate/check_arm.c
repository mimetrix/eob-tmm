/* Reuse the VALIDATED test_tramp from test_tramp.S. Put the hand-built target in
 * a page mmap'd with an address HINT near test_tramp, so the call is in rel32
 * range. If the kernel honours the hint the arm succeeds; if not, ls_arm's range
 * check refuses cleanly (which is itself correct behaviour, and reported). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
int ls_arm(void*,void*); int ls_disarm(void*);
extern void test_tramp(void);
extern volatile int g_tramp_hits, g_skip_body;
typedef uint64_t (*fn2)(uint64_t,uint64_t);

int main(void){
    int fails=0;
    /* hint: a page ~1MB below test_tramp, well inside rel32 */
    void *hint=(void*)(((uintptr_t)test_tramp - 0x100000) & ~0xfffUL);
    uint8_t *pg=mmap(hint,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(pg==(void*)-1){perror("mmap");return 1;}
    long d=(long)((char*)test_tramp-(char*)pg);
    printf("  target page %p, test_tramp %p, distance=%ld (rel32 ok=%d)\n",
        (void*)pg,(void*)test_tramp,d,(d>-2000000000L&&d<2000000000L));

    int i=0;
    pg[i++]=0xf3;pg[i++]=0x0f;pg[i++]=0x1e;pg[i++]=0xfa;
    pg[i++]=0x90;pg[i++]=0x90;pg[i++]=0x90;pg[i++]=0x90;pg[i++]=0x90;
    pg[i++]=0xb8;pg[i++]=103;pg[i++]=0;pg[i++]=0;pg[i++]=0;pg[i++]=0xc3;
    __builtin___clear_cache((char*)pg,(char*)pg+i);
    fn2 fn=(fn2)pg;

    g_tramp_hits=0; uint64_t r=fn(1,2);
    printf("  unarmed:        ret=%llu hits=%d\n",(unsigned long long)r,g_tramp_hits);
    if(r!=103||g_tramp_hits!=0){puts("  FAIL baseline");fails++;}else puts("  ok   target runs, no trampoline");

    int a=ls_arm(pg,(void*)test_tramp);
    if(a!=0){printf("  ls_arm refused (rc=%d) --- see message above\n",a);
             puts("  (if refusal is the rel32 range, the hint was not honoured; rerun)"); return 2;}
    g_tramp_hits=0; g_skip_body=0; r=fn(1,2);
    printf("  armed(through): ret=%llu hits=%d\n",(unsigned long long)r,g_tramp_hits);
    if(g_tramp_hits!=1||r!=103){puts("  FAIL fall-through");fails++;}else puts("  ok   trampoline fired, body still ran");

    g_tramp_hits=0; g_skip_body=1; r=fn(1,2);
    printf("  armed(skip):    ret=%llu hits=%d\n",(unsigned long long)r,g_tramp_hits);
    if(g_tramp_hits!=1||r!=0){puts("  FAIL skip");fails++;}else puts("  ok   trampoline fired, body skipped");

    if(ls_disarm(pg)!=0){puts("  FAIL disarm");fails++;}
    g_tramp_hits=0; r=fn(1,2);
    printf("  disarmed:       ret=%llu hits=%d\n",(unsigned long long)r,g_tramp_hits);
    if(r!=103||g_tramp_hits!=0){puts("  FAIL restore");fails++;}else puts("  ok   back to baseline");

    printf("\n  %s\n",fails?"FAILURES":"arming validated end to end: install, effect, reverse");
    return fails;
}
