#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ubpf_int.h"

#define INSN(op,dst,src,off,imm) (uint8_t){op}, (uint8_t)((dst)|((src)<<4)), \
    (uint8_t)((off)&0xff), (uint8_t)(((off)>>8)&0xff), \
    (uint8_t)((imm)&0xff), (uint8_t)(((imm)>>8)&0xff), \
    (uint8_t)(((imm)>>16)&0xff), (uint8_t)(((imm)>>24)&0xff)

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    /* r0=42; *(u64*)(r10-8)=r0; r0=0; r0=*(u64*)(r10-8); exit */
    uint8_t prog[] = {
        INSN(0xb7,0,0,0,42),
        INSN(0x7b,10,0,-8,0),  /* STXDW: *(u64*)(r10-8) = r0 */
        INSN(0xb7,0,0,0,0),
        INSN(0x79,0,10,-8,0), /* LDXDW: r0 = *(u64*)(r10-8) */
        INSN(0x95,0,0,0,0),
    };
    pid_t p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        int load_rc = ubpf_load(vm, prog, sizeof(prog), &e);
        printf("load_rc=%d", load_rc);
        if (load_rc != 0) { printf(" err=%s\n", e); _exit(1); }
        printf(" num_insts=%u\n", vm->num_insts);
        size_t sz = 65536;
        uint8_t buf[65536];
        memset(buf, 0xcc, sizeof(buf));
        int rc = ubpf_translate(vm, buf, &sz, &e);
        printf("translate_rc=%d size=%zu\n", rc, sz);
        if (rc != 0) { printf(" err=%s\n", e); _exit(1); }
        for (size_t i = 0; i < sz && i < 120; i += 4) {
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
