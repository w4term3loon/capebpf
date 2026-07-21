#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ubpf.h"

#if defined(__CHERI_PURE_CAPABILITY__)
#define JIT_LABEL "cheri_jit"
#else
#define JIT_LABEL "jit"
#endif

static void test(const char *name, const uint8_t *prog, size_t plen, uint64_t expected) {
    (void)name;

    pid_t p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        int lc = ubpf_load(vm, prog, plen, &e);
        if (lc != 0) { printf("  interp: LOAD FAIL: %s\n", e); _exit(1); }
        uint64_t r; int rc = ubpf_exec(vm, NULL, 0, &r);
        if (rc != 0) printf("  interp: BLOCKED\n");
        else printf("  interp: r0=%llu (expect %llu) %s\n",
            (unsigned long long)r, (unsigned long long)expected,
            r == expected ? "OK" : "MISMATCH");
        ubpf_destroy(vm); _exit(0);
    }
    int s; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("  interp: CRASH sig %d\n", WTERMSIG(s));
    p = fork();
    if (p == 0) {
        struct ubpf_vm *vm = ubpf_create();
        char *e = NULL;
        int lc = ubpf_load(vm, prog, plen, &e);
        if (lc != 0) { printf("  %s: LOAD FAIL: %s\n", JIT_LABEL, e); _exit(1); }
        ubpf_jit_fn j = ubpf_compile(vm, &e);
        if (!j) { printf("  %s: compile FAILED: %s\n", JIT_LABEL, e); _exit(1); }
        uint64_t r = j(NULL, 0);
        printf("  %s: r0=%llu (expect %llu) %s\n", JIT_LABEL,
            (unsigned long long)r, (unsigned long long)expected,
            r == expected ? "OK" : "MISMATCH");
        ubpf_destroy(vm); _exit(0);
    }
    s = 0; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("  %s: CRASH sig %d\n", JIT_LABEL, WTERMSIG(s));
}

#define INSN(op,dst,src,off,imm) (uint8_t){op}, (uint8_t)((dst)|((src)<<4)), \
    (uint8_t)((off)&0xff), (uint8_t)(((off)>>8)&0xff), \
    (uint8_t)((imm)&0xff), (uint8_t)(((imm)>>8)&0xff), \
    (uint8_t)(((imm)>>16)&0xff), (uint8_t)(((imm)>>24)&0xff)

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. JEQ_IMM taken: r0=0; if r0==0 goto +2; r0=99; exit; r0=42; exit */
    {
        uint8_t p[] = {
            INSN(0xb7,0,0,0,0),       /* r0 = 0 */
            INSN(0x15,0,0,2,0),       /* if r0 == 0, goto +2 */
            INSN(0xb7,0,0,0,99),      /* r0 = 99 (skipped) */
            INSN(0x95,0,0,0,0),       /* exit (skipped) */
            INSN(0xb7,0,0,0,42),      /* r0 = 42 */
            INSN(0x95,0,0,0,0),       /* exit */
        };
        printf("test1: JEQ_IMM taken (r0==0 -> +2)\n");
        test("jeq_imm_taken", p, sizeof(p), 42);
    }

    /* 2. JEQ_IMM not taken: r0=1; if r0==0 goto +1; r0=42; exit */
    {
        uint8_t p[] = {
            INSN(0xb7,0,0,0,1),       /* r0 = 1 */
            INSN(0x15,0,0,1,0),       /* if r0 == 0, goto +1 (not taken) */
            INSN(0xb7,0,0,0,42),      /* r0 = 42 */
            INSN(0x95,0,0,0,0),       /* exit */
        };
        printf("test2: JEQ_IMM not taken (r0==1)\n");
        test("jeq_imm_not_taken", p, sizeof(p), 42);
    }

    /* 3. JGT_IMM: r0=5; if r0>3 goto +2; r0=99; exit; r0=42; exit */
    {
        uint8_t p[] = {
            INSN(0xb7,0,0,0,5),       /* r0 = 5 */
            INSN(0x25,0,0,2,3),       /* if r0 > 3, goto +2 */
            INSN(0xb7,0,0,0,99),      /* r0 = 99 (skipped) */
            INSN(0x95,0,0,0,0),       /* exit (skipped) */
            INSN(0xb7,0,0,0,42),      /* r0 = 42 */
            INSN(0x95,0,0,0,0),       /* exit */
        };
        printf("test3: JGT_IMM (r0=5 > 3 -> +2)\n");
        test("jgt_imm", p, sizeof(p), 42);
    }

    /* 4. JNE_IMM: r0=7; if r0!=0 goto +1; r0=99; exit */
    {
        uint8_t p[] = {
            INSN(0xb7,0,0,0,7),       /* r0 = 7 */
            INSN(0x55,0,0,1,0),       /* if r0 != 0, goto +1 */
            INSN(0xb7,0,0,0,99),      /* r0 = 99 (skipped) */
            INSN(0xb7,0,0,0,42),      /* r0 = 42 */
            INSN(0x95,0,0,0,0),       /* exit */
        };
        printf("test4: JNE_IMM (r0=7 != 0 -> +1)\n");
        test("jne_imm", p, sizeof(p), 42);
    }

    /* 5. JEQ_REG: r1=5; r2=5; if r1==r2 goto +1; r0=99; exit */
    {
        uint8_t p[] = {
            INSN(0xb7,1,0,0,5),       /* r1 = 5 */
            INSN(0xb7,2,0,0,5),       /* r2 = 5 */
            INSN(0x1d,1,2,1,0),       /* if r1 == r2, goto +1 */
            INSN(0xb7,0,0,0,99),      /* r0 = 99 (skipped) */
            INSN(0xb7,0,0,0,42),      /* r0 = 42 */
            INSN(0x95,0,0,0,0),       /* exit */
        };
        printf("test5: JEQ_REG taken (r1==r2 -> +1)\n");
        test("jeq_reg", p, sizeof(p), 42);
    }

    /* 6. Loop: r0=0; r1=3; L: r0+=1; r1-=1; if r1!=0 goto L; exit
     *    eBPF jump target = pc + 1 + offset
     *    pc 4, want to goto pc 2: offset = 2 - 4 - 1 = -3 */
    {
        uint8_t p[] = {
            INSN(0xb7,0,0,0,0),       /* 0: r0 = 0 */
            INSN(0xb7,1,0,0,3),       /* 1: r1 = 3 */
            INSN(0x07,0,0,0,1),       /* 2: r0 += 1 */
            INSN(0x17,1,0,0,1),       /* 3: r1 -= 1 */
            INSN(0x55,1,0,-3,0),      /* 4: if r1 != 0, goto pc 2 (offset -3) */
            INSN(0x95,0,0,0,0),       /* 5: exit */
        };
        printf("test6: loop (3 iterations, r0 should be 3)\n");
        test("loop", p, sizeof(p), 3);
    }

    return 0;
}
