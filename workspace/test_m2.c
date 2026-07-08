#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ubpf.h"

static void test(const char *name, const uint8_t *prog, size_t plen, uint64_t expected, void *mem, size_t mem_len) {
    /* Interpreter */
    pid_t p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        ubpf_load(vm, prog, plen, &e);
        uint64_t r;
        int rc = ubpf_exec(vm, mem, mem_len, &r);
        if (rc != 0) printf("  interp: BLOCKED\n");
        else printf("  interp: r0=%llu (expect %llu) %s\n",
            (unsigned long long)r, (unsigned long long)expected,
            r == expected ? "OK" : "MISMATCH");
        ubpf_destroy(vm);
        _exit(0);
    }
    int s; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("  interp: CRASH sig %d\n", WTERMSIG(s));

    /* CHERI JIT */
    p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        ubpf_load(vm, prog, plen, &e);
        ubpf_jit_fn j = ubpf_compile(vm, &e);
        if (!j) { printf("  cheri_jit: compile FAILED: %s\n", e); _exit(1); }
        uint64_t r = j(mem, mem_len);
        printf("  cheri_jit: r0=%llu (expect %llu) %s\n",
            (unsigned long long)r, (unsigned long long)expected,
            r == expected ? "OK" : "MISMATCH");
        ubpf_destroy(vm);
        _exit(0);
    }
    s = 0; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("  cheri_jit: CRASH sig %d\n", WTERMSIG(s));
}

#define INSN(op,dst,src,off,imm) (uint8_t){op}, (uint8_t)((dst)|((src)<<4)), (uint8_t)((off)&0xff), (uint8_t)(((off)>>8)&0xff), (uint8_t)((imm)&0xff), (uint8_t)(((imm)>>8)&0xff), (uint8_t)(((imm)>>16)&0xff), (uint8_t)(((imm)>>24)&0xff)

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. mov64 imm: r0 = 42; exit */
    {
        uint8_t p[] = { INSN(0xb7,0,0,0,42), INSN(0x95,0,0,0,0) };
        printf("test1: mov64_imm r0=42\n");
        test("mov64_imm", p, sizeof(p), 42, NULL, 0);
    }

    /* 2. mov64 reg: r1 = 42; r0 = r1; exit */
    {
        uint8_t p[] = { INSN(0xb7,1,0,0,42), INSN(0xbf,0,1,0,0), INSN(0x95,0,0,0,0) };
        printf("test2: mov64_reg r1=42, r0=r1\n");
        test("mov64_reg", p, sizeof(p), 42, NULL, 0);
    }

    /* 3. add64 imm: r0 = 10; r0 += 32; exit */
    {
        uint8_t p[] = { INSN(0xb7,0,0,0,10), INSN(0x07,0,0,0,32), INSN(0x95,0,0,0,0) };
        printf("test3: add64_imm r0=10, r0+=32\n");
        test("add64_imm", p, sizeof(p), 42, NULL, 0);
    }

    /* 4. sub64 imm: r0 = 100; r0 -= 58; exit */
    {
        uint8_t p[] = { INSN(0xb7,0,0,0,100), INSN(0x17,0,0,0,58), INSN(0x95,0,0,0,0) };
        printf("test4: sub64_imm r0=100, r0-=58\n");
        test("sub64_imm", p, sizeof(p), 42, NULL, 0);
    }

    /* 5. add64 reg: r1 = 20; r2 = 22; r0 = r1; r0 += r2; exit */
    {
        uint8_t p[] = {
            INSN(0xb7,1,0,0,20), INSN(0xb7,2,0,0,22),
            INSN(0xbf,0,1,0,0), INSN(0x0f,0,2,0,0), INSN(0x95,0,0,0,0)
        };
        printf("test5: add64_reg r1=20, r2=22, r0=r1+r2\n");
        test("add64_reg", p, sizeof(p), 42, NULL, 0);
    }

    /* 6. sub64 reg: r1 = 100; r2 = 58; r0 = r1; r0 -= r2; exit */
    {
        uint8_t p[] = {
            INSN(0xb7,1,0,0,100), INSN(0xb7,2,0,0,58),
            INSN(0xbf,0,1,0,0), INSN(0x1f,0,2,0,0), INSN(0x95,0,0,0,0)
        };
        printf("test6: sub64_reg r1=100, r2=58, r0=r1-r2\n");
        test("sub64_reg", p, sizeof(p), 42, NULL, 0);
    }

    /* 7. compound: r0 = 5; r0 += 10; r0 += 20; r0 += 7; exit (expect 42) */
    {
        uint8_t p[] = {
            INSN(0xb7,0,0,0,5), INSN(0x07,0,0,0,10),
            INSN(0x07,0,0,0,20), INSN(0x07,0,0,0,7), INSN(0x95,0,0,0,0)
        };
        printf("test7: compound add r0=5+10+20+7\n");
        test("compound_add", p, sizeof(p), 42, NULL, 0);
    }

    return 0;
}
