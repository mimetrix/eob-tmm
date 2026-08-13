/* check_swap_integrated.c --- the safe swap folded into the real armed path.
 *
 * check_swap_realtext proved the text_poke_bp swap safe on real private .text, but
 * armed a STUB (test_tramp). check_integrated proved the real trampoline + real VM
 * decide control flow, but single-threaded. This folds them: N worker threads, one
 * per core, hammer a REAL function while one armer thread arms/disarms the REAL
 * trampoline onto its pad via text_poke_bp (/proc/self/mem + membarrier). Every
 * armed call runs the REAL VM (a PREVAIL-verified BLOCK shield -> SAFE_RETURN).
 *
 * Legal worker returns:
 *   0xBEEF  the body ran   (disarmed, or a core caught mid-patch and redirected)
 *   0       safe value     (armed: VM said SAFE_RETURN, body skipped)
 * Anything else is corruption; a fault is a failed swap. The VM's verdict is in
 * the loop, on every armed call, under contention.
 *
 * Build (x86-64 box, bumped ubpf):
 *   gcc -O2 -fcf-protection=full -fpatchable-function-entry=5,0 -pthread -I. \
 *     -I~/ubpf-new/vm/inc -I~/ubpf-new/build/vm check_swap_integrated.c \
 *     ls_vm.c ls_vm_config.c ls_tramp.c trampoline_x86_64.S \
 *     ~/ubpf-new/build/lib/libubpf.a -o check_swap_integrated
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <linux/membarrier.h>
#include "ls_vm.h"

static void sync_cores(void){ syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0); }

extern void ls_trampoline_entry(void);
extern unsigned char ls_tramp_slot_insn[];   /* movl $imm32,%edi ; +1 is the slot imm */

#define BODY_VALUE 0xBEEFu
static volatile uint64_t g_body_hits;
__attribute__((noinline,used))
static uint64_t victim(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e)
{ (void)a;(void)b;(void)c;(void)d;(void)e; g_body_hits++; return BODY_VALUE; }

typedef uint64_t (*fn5)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static uint8_t *g_target, *g_pad;
static int g_memfd = -1;
static volatile int g_stop, g_widen;
static _Atomic long g_faults, g_corrupt, g_calls, g_cycles, g_traps;

static __thread sigjmp_buf g_jb;
static __thread int g_in_call;
static _Atomic int g_fault_seen; static volatile int g_fsig; static volatile long g_frip_off;

static void poke1(uint8_t*a,uint8_t v){ if(pwrite(g_memfd,&v,1,(off_t)(uintptr_t)a)!=1){perror("poke1");_exit(5);} }
static void poke4(uint8_t*a,const void*p){ if(pwrite(g_memfd,p,4,(off_t)(uintptr_t)a)!=4){perror("poke4");_exit(5);} }

static void trap_handler(int sig,siginfo_t*si,void*uc)
{
    (void)sig;(void)si;
    ucontext_t*c=(ucontext_t*)uc;
    uint8_t*rip=(uint8_t*)c->uc_mcontext.gregs[REG_RIP];
    if(rip==g_pad+1){ c->uc_mcontext.gregs[REG_RIP]=(greg_t)(uintptr_t)(g_pad+5);  /* -> body */
        __atomic_fetch_add(&g_traps,1,__ATOMIC_RELAXED); return; }
    _exit(4);
}
static void fault_handler(int sig,siginfo_t*si,void*uc)
{
    if(g_in_call){
        if(!__atomic_exchange_n(&g_fault_seen,1,__ATOMIC_RELAXED)){
            ucontext_t*c=(ucontext_t*)uc; g_fsig=sig;
            g_frip_off=(long)((uint8_t*)c->uc_mcontext.gregs[REG_RIP]-g_pad); (void)si; }
        __atomic_fetch_add(&g_faults,1,__ATOMIC_RELAXED); siglongjmp(g_jb,1);
    }
    _exit(2);
}

static void do_arm(void)
{
    int32_t d=(int32_t)((uint8_t*)ls_trampoline_entry-(g_pad+5));
    poke1(g_pad,0xcc);      sync_cores();
    for(volatile int z=0;z<g_widen;z++){}
    poke4(g_pad+1,&d);      sync_cores();
    poke1(g_pad,0xe8);      sync_cores();
}
static void do_disarm(void)
{
    static const uint8_t nops4[4]={0x90,0x90,0x90,0x90};
    poke1(g_pad,0xcc);      sync_cores();
    poke4(g_pad+1,nops4);   sync_cores();
    poke1(g_pad,0x90);      sync_cores();
}

static void* worker(void*arg)
{
    (void)arg;
    struct sigaction sa={0}; sa.sa_sigaction=fault_handler; sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL); sigaction(SIGILL,&sa,NULL); sigaction(SIGBUS,&sa,NULL);
    fn5 f=(fn5)g_target;
    while(!g_stop){
        if(sigsetjmp(g_jb,1)==0){
            g_in_call=1;
            uint64_t r=f(1,2,3,4,5);
            g_in_call=0;
            __atomic_fetch_add(&g_calls,1,__ATOMIC_RELAXED);
            if(r!=BODY_VALUE && r!=0) __atomic_fetch_add(&g_corrupt,1,__ATOMIC_RELAXED);
        } else g_in_call=0;
    }
    return NULL;
}
static void* armer(void*arg)
{ (void)arg; while(!g_stop){ do_arm(); do_disarm(); __atomic_fetch_add(&g_cycles,2,__ATOMIC_RELAXED);} return NULL; }

static void* slurp(const char*p,size_t*n){ FILE*f=fopen(p,"rb"); if(!f){perror(p);return NULL;}
    fseek(f,0,SEEK_END);*n=ftell(f);fseek(f,0,SEEK_SET); void*b=malloc(*n);
    if(!b||fread(b,1,*n,f)!=*n){fclose(f);return NULL;} fclose(f); return b; }

int main(int argc,char**argv)
{
    if(argc<2){ fprintf(stderr,"usage: %s demo_block.o [workers] [seconds] [widen]\n",argv[0]); return 2; }
    int ncpu=(int)sysconf(_SC_NPROCESSORS_ONLN);
    int nworkers=(argc>2)?atoi(argv[2]):(ncpu>2?ncpu-1:1);
    int seconds =(argc>3)?atoi(argv[3]):20;
    g_widen     =(argc>4)?atoi(argv[4]):200;

    g_target=(uint8_t*)victim; g_pad=g_target+4;
    if(!(g_target[0]==0xf3&&g_target[1]==0x0f&&g_target[2]==0x1e&&g_target[3]==0xfa)){
        printf("victim has no endbr64 --- rebuild with -fcf-protection=full\n"); return 3; }
    for(int k=0;k<5;k++) if(g_pad[k]!=0x90){ printf("pad not nops --- rebuild with -fpatchable-function-entry=5,0\n"); return 3; }

    /* bring up the VM and load the BLOCK shield (SAFE_RETURN) */
    if(!ls_vm_init()){ puts("ls_vm_init failed"); return 1; }
    size_t n; void*blk=slurp(argv[1],&n); if(!blk) return 2;
    int slot=ls_vm_arm(blk,n,"fentry/demo_block","shield",LS_MODE_ENFORCE);
    if(slot<0){ printf("shield load failed (%d)\n",slot); return 1; }

    g_memfd=open("/proc/self/mem",O_RDWR); if(g_memfd<0){perror("mem");return 1;}
    /* bake the slot into the trampoline's immediate */
    { int32_t s=slot; if(pwrite(g_memfd,&s,4,(off_t)(uintptr_t)(ls_tramp_slot_insn+1))!=4){perror("slot");return 1;}
      __builtin___clear_cache((char*)ls_tramp_slot_insn,(char*)ls_tramp_slot_insn+8); }

    syscall(SYS_membarrier,MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,0,0);
    struct sigaction ta={0}; ta.sa_sigaction=trap_handler; ta.sa_flags=SA_SIGINFO; sigaction(SIGTRAP,&ta,NULL);

    /* sanity: armed once, single-thread, before the storm */
    do_arm();   uint64_t ra=((fn5)g_target)(1,2,3,4,5);
    do_disarm(); uint64_t rd=((fn5)g_target)(1,2,3,4,5);
    printf("  preflight: armed->%#llx (want 0x0)  disarmed->%#llx (want 0xbeef)\n",
           (unsigned long long)ra,(unsigned long long)rd);
    if(ra!=0||rd!=BODY_VALUE){ puts("  FAIL preflight --- VM/trampoline path wrong, not running storm"); return 1; }

    printf("  slot=%d  cores=%d workers=%d seconds=%d widen=%d  victim=%p tramp=%p\n",
           slot,ncpu,nworkers,seconds,g_widen,(void*)g_target,(void*)ls_trampoline_entry);

    pthread_t th[256],ar;
    for(int w=0;w<nworkers&&w<256;w++){ pthread_create(&th[w],NULL,worker,NULL);
        cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(w%ncpu,&cs); pthread_setaffinity_np(th[w],sizeof cs,&cs); }
    pthread_create(&ar,NULL,armer,NULL);
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(nworkers%ncpu,&cs); pthread_setaffinity_np(ar,sizeof cs,&cs);

    for(int e=0;e<seconds;e+=30){
        int chunk=(seconds-e)<30?(seconds-e):30; sleep(chunk);
        long f=__atomic_load_n(&g_faults,__ATOMIC_RELAXED), c=__atomic_load_n(&g_corrupt,__ATOMIC_RELAXED);
        printf("  [%4ds] calls=%-12ld cycles=%-10ld traps=%-11ld faults=%ld corrupt=%ld\n",
               e+chunk,__atomic_load_n(&g_calls,__ATOMIC_RELAXED),__atomic_load_n(&g_cycles,__ATOMIC_RELAXED),
               __atomic_load_n(&g_traps,__ATOMIC_RELAXED),f,c);
        if(__atomic_load_n(&g_fault_seen,__ATOMIC_RELAXED)){
            const char*nm=g_fsig==SIGSEGV?"SIGSEGV":g_fsig==SIGILL?"SIGILL":g_fsig==SIGBUS?"SIGBUS":"?";
            printf("        first fault: %s rip=pad%+ld\n",nm,g_frip_off); }
        fflush(stdout);
    }
    g_stop=1;
    for(int w=0;w<nworkers&&w<256;w++) pthread_join(th[w],NULL);
    pthread_join(ar,NULL);

    struct ls_stats st; ls_vm_stats(slot,&st);
    printf("  calls=%ld cycles=%ld int3_traps=%ld  |  VM fired=%llu safe_returns=%llu errors=%llu\n",
           g_calls,g_cycles,g_traps,(unsigned long long)st.fired,
           (unsigned long long)st.safe_returns,(unsigned long long)st.errors);
    printf("  FAULTS=%ld  CORRUPT_RETURNS=%ld\n",g_faults,g_corrupt);
    long bad=g_faults+g_corrupt;
    printf("\n  %s\n", bad ? "FAILED: swap+VM under load produced a fault or garbage"
                           : "CLEAN: real trampoline + real VM, armed/disarmed under multi-core load");
    ls_vm_fini();
    return bad?1:0;
}
