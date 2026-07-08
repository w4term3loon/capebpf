#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ubpf.h"

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint8_t prog[] = {0xb7,0,0,0,0x2a,0,0,0, 0x95,0,0,0,0,0,0,0};

    /* Try CHERI JIT in fork */
    pid_t p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        ubpf_load(vm, prog, sizeof(prog), &e);

        /* Use ubpf_translate to get the raw bytes */
        size_t sz = 65536;
        uint8_t buf[65536];
        int rc = ubpf_translate(vm, buf, &sz, &e);
        if (rc != 0) { printf("translate failed: %s\n", e); _exit(1); }
        printf("JIT code size: %zu bytes\n", sz);
        printf("JIT code hex:\n");
        for (size_t i = 0; i < sz; i += 4) {
            uint32_t w = (uint32_t)buf[i] | ((uint32_t)buf[i+1] << 8) |
                       ((uint32_t)buf[i+2] << 16) | ((uint32_t)buf[i+3] << 24);
            printf("  %4zu: %08x\n", i, w);
        }
        _exit(0);
    }
    int s; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("CRASH sig %d\n", WTERMSIG(s));
    return 0;
}
