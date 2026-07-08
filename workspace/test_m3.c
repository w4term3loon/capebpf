#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ubpf.h"

static void test(const char *name, const uint8_t *prog, size_t plen, uint64_t expected) {
    pid_t p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        ubpf_load(vm, prog, plen, &e);
        uint64_t r;
        int rc = ubpf_exec(vm, NULL, 0, &r);
        if (rc != 0) printf("  interp: BLOCKED\n");
        else printf("  interp: r0=%llu (expect %llu) %s\n",
            (unsigned long long)r, (unsigned long long)expected,
            r == expected ? "OK" : "MISMATCH");
        ubpf_destroy(vm);
        _exit(0);
    }
    int s; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("  interp: CRASH sig %d\n", WTERMSIG(s));

    p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        ubpf_load(vm, prog, plen, &e);
        ubpf_jit_fn j = ubpf_compile(vm, &e);
        if (!j) { printf("  cheri_jit: compile FAILED: %s\n", e); _exit(1); }
        uint64_t r = j(NULL, 0);
        printf("  cheri_jit: r0=%llu (expect %llu) %s\n",
            (unsigned long long)r, (unsigned long long)expected,
            r == expected ? "OK" : "MISMATCH");
        ubpf_destroy(vm);
        _exit(0);
    }
    s = 0; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("  cheri_jit: CRASH sig %d\n", WTERMSIG(s));
}

#define INSN(op,dst,src,off,imm) (uint8_t){op}, (uint8_t)((dst)|((src)<<4)), \
    (uint8_t)((off)&0xff), (uint8_t)(((off)>>8)&0xff), \
    (uint8_t)((imm)&0xff), (uint8_t)(((imm)>>8)&0xff), \
    (uint8_t)(((imm)>>16)&0xff), (uint8_t)(((imm)>>24)&0xff)

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. Stack store + load: r0=42; *(u64*)(r10-8)=r0; r0=0; r0=*(u64*)(r10-8); exit */
    {
        uint8_t p[] = {
            INSN(0xb7,0,0,0,42),    /* r0 = 42 */
            INSN(0x7b,0xa,0,-8,0),  /* *(u64*)(r10 - 8) = r0 */
            INSN(0xb7,0,0,0,0),     /* r0 = 0 */
            INSN(0x79,0,0,-8,0),   /* r0 = *(u64*)(r10 - 8) */
            INSN(0x95,0,0,0,0),     /* exit */
        };
        printf("test1: stack store+load (r10-8)\n");
        test("stack_store_load", p, sizeof(p), 42);
    }

    /* 2. Just stack load from uninitialized slot: r0=*(u64*)(r10-8); exit */
    {
        uint8_t p[] = {
            INSN(0x79,0,0,-8,0),   /* r0 = *(u64*)(r10 - 8) */
            INSN(0x95,0,0,0,0),     /* exit */
        };
        printf("test2: stack load uninit (r10-8)\n");
        test("stack_load_uninit", p, sizeof(p), 0);
    }

    /* 3. Store+load with larger offset: r10-256 */
    {
        uint8_t p[] = {
            INSN(0xb7,0,0,0,99),     /* r0 = 99 */
            INSN(0x7b,0xa,0,-256,0), /* *(u64*)(r10 - 256) = r0 */
            INSN(0xb7,0,0,0,0),      /* r0 = 0 */
            INSN(0x79,0,0,-256,0),  /* r0 = *(u64*)(r10 - 256) */
            INSN(0x95,0,0,0,0),      /* exit */
        };
        printf("test3: stack store+load (r10-256)\n");
        test("stack_store_load_256", p, sizeof(p), 99);
    }

    return 0;
}
