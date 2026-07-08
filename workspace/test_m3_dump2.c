#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ubpf_int.h"

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* r0=42; *(u64*)(r10-8)=r0; r0=0; r0=*(u64*)(r10-8); exit */
    uint8_t prog[] = {
        0xb7,0,0,0,42,0,0,0,
        0x7b,0xa,0,0xf8,0xff,0,0,0,
        0xb7,0,0,0,0,0,0,0,
        0x79,0,0,0xf8,0xff,0,0,0,
        0x95,0,0,0,0,0,0,0,
    };
    pid_t p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        ubpf_load(vm, prog, sizeof(prog), &e);
        size_t sz = 65536;
        uint8_t buf[65536];
        int rc = ubpf_translate(vm, buf, &sz, &e);
        if (rc != 0) { printf("translate failed: %s\n", e); _exit(1); }
        printf("SIZE=%zu\n", sz);
        for (size_t i = 0; i < sz && i < 120; i += 4) {
            uint32_t w = (uint32_t)buf[i] | ((uint32_t)buf[i+1] << 8) |
                       ((uint32_t)buf[i+2] << 16) | ((uint32_t)buf[i+3] << 24);
            printf("  %4zu: %08x\n", i, w);
        }
        _exit(0);
    }
    int s; waitpid(p, &s, 0);
    return 0;
}
