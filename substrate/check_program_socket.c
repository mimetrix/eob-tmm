/* Actual program socket handler and prepare handoff, with authored functions.
 * Audit output is outside this test. The signature verifier is the real one. */
#include "ls_vm_load.c"
#include "ls_vm.c"
#include <assert.h>

unsigned bodies;
extern uint64_t program_alpha(uint64_t a, uint64_t b);
extern uint64_t program_beta(uint64_t a, uint64_t b);
static const char *build_id;
static _Atomic unsigned ready;
const char *ls_audit_build_id(void) { return build_id; }
void ls_audit_note_reply(const char *text) { (void)text; }
int ls_tp_publish_raw(int slot, const void *record, unsigned long length)
{ (void)slot; (void)record; (void)length; return 0; }
int ls_tp_emit_shield(int slot, unsigned gen, unsigned mode, unsigned verdict,
                      const void *ctx, unsigned long length)
{ (void)slot; (void)gen; (void)mode; (void)verdict; (void)ctx; (void)length; return 0; }
void ls_fexit_enter(void) { abort(); }
void ls_fexit_leave(void) { abort(); }

static void *prepare(void *unused)
{
    (void)unused;
    assert(ls_vm_init());
    ls_prep_timer_on = 1;
    atomic_store(&ready, 1);
    for (;;) {
        ls_prep_run_pending();
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    assert(program_alpha(0, 0) == 0 && program_beta(0, 0) == 10);
    build_id = argv[2];
    g_ls_config.session = 1;
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, prepare, NULL));
    while (!atomic_load(&ready)) {
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    assert(server >= 0 && strlen(argv[1]) < sizeof address.sun_path);
    strcpy(address.sun_path, argv[1]);
    assert(!bind(server, (struct sockaddr *)&address, sizeof address));
    assert(!chmod(argv[1], 0600) && !listen(server, 4));
    puts("READY"); fflush(stdout);
    for (;;) {
        int fd = accept(server, NULL, NULL);
        assert(fd >= 0);
        struct shield_msg *seen = NULL, copy;
        handle_msg(fd, &seen, &copy);
        close(fd);
    }
}
