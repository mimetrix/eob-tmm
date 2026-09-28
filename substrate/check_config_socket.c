/* Actual loader framing/config handler, with only unrelated TMM paths removed
 * by linker section GC. Session/binding are fixture data, not signature proof. */
#include "ls_vm_load.c"
#include <assert.h>

/* The real reply writer is used; the audit sink is outside this socket test. */
void ls_audit_note_reply(const char *text) { (void)text; }

int main(int argc, char **argv)
{
    assert(argc == 2);
    g_ls_config.session = 0x123456789;
    uint8_t sha[32];
    memset(sha, 0xab, sizeof sha);
    uint64_t instance = ls_config_new_instance(&g_ls_config, 5);
    assert(!ls_config_bind(&g_ls_config, 5, instance, sha));
    int server = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    assert(strlen(argv[1]) < sizeof address.sun_path);
    strcpy(address.sun_path, argv[1]);
    assert(server >= 0 && !bind(server, (struct sockaddr *)&address, sizeof address));
    assert(!listen(server, 4));
    puts("READY"); fflush(stdout);
    for (;;) {
        int fd = accept(server, NULL, NULL);
        assert(fd >= 0);
        unsigned char *buffer = ls_load_buf_alloc();
        struct shield_msg *seen = NULL, copy;
        assert(buffer);
        if (!ls_load_receive(fd, buffer, &seen, &copy)) {
            struct shield_msg *m = (void *)buffer;
            if (m->op == SHIELD_OP_CONFIG_STATUS || m->op == SHIELD_OP_CONFIG_PUBLISH)
                ls_handle_config(fd, m);
            else reply(fd, "ERR test accepts configuration operations only\n");
        }
        ls_load_buf_free(buffer);
        close(fd);
    }
}
