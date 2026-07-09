/*
 * test_instruction_matrix.c
 *
 * Systematically tests every instruction category from mmap PROT_EXEC
 * memory on CheriBSD purecap. Each test runs in a forked child so
 * crashes are isolated.
 *
 * Output is captured and archived as primary research data.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

#ifndef SIGPROT
#define SIGPROT 34
#endif

static int run_test(const char *name, const uint32_t *code, size_t code_len) {
    void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == (void*)-1) { printf("  %s: mmap FAILED\n", name); return -1; }
    memcpy(p, code, code_len);

    pid_t pid = fork();
    if (pid == 0) {
        uint64_t r = ((uint64_t(*)(void*,size_t))p)(NULL, 0);
        printf("  %s: OK  r0=%llu\n", name, (unsigned long long)r);
        _exit(0);
    }
    int s; waitpid(pid, &s, 0);
    if (WIFSIGNALED(s)) {
        int sig = WTERMSIG(s);
        const char *sn = (sig == 34) ? "SIGPROT" :
                         (sig == 11) ? "SIGSEGV" : "?";
        printf("  %s: CRASH  %s(%d)\n", name, sn, sig);
        munmap(p, 4096);
        return sig;
    }
    int rc = WEXITSTATUS(s);
    if (rc != 0) printf("  %s: EXIT(%d)\n", name, rc);
    munmap(p, 4096);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Allocate a separate RW data page for store target tests */
    void *data_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    uint64_t data_addr = (uint64_t)(uintptr_t)data_page;

    /* Allocate a separate RW stack page for stack-store tests */
    void *stack_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    uint64_t stack_addr = (uint64_t)(uintptr_t)stack_page;

    printf("=== Instruction Matrix Test on CheriBSD Purecap QEMU Morello ===\n");
    printf("data_page=0x%llx  stack_page=0x%llx\n\n",
           (unsigned long long)data_addr, (unsigned long long)stack_addr);

    /* Helpers to load a 64-bit address into X19 */
    #define MOVZ_X19(lo)  (0xd2800000U | (((lo) & 0xffff) << 5) | 19)
    #define MOVK_X19(mid,shift) (0xf2a00000U | ((((mid) >> (shift)) & 0xffff) << 5) | 19)

    uint32_t movz = 0xd2800000U | ((data_addr & 0xffff) << 5) | 19;
    uint32_t movk16 = 0xf2a00000U | (((data_addr >> 16) & 0xffff) << 5) | 19;
    uint32_t movk32 = 0xf2c00000U | (((data_addr >> 32) & 0xffff) << 5) | 19;

    uint32_t smovz = 0xd2800000U | ((stack_addr & 0xffff) << 5) | 19;
    uint32_t smovk16 = 0xf2a00000U | (((stack_addr >> 16) & 0xffff) << 5) | 19;
    uint32_t smovk32 = 0xf2c00000U | (((stack_addr >> 32) & 0xffff) << 5) | 19;

    /* ---- 1. Morello sub csp ---- */
    run_test("sub_csp", (uint32_t[]){
        0x028083f0, 0xd2800540, 0x020083f0, 0xc2c253c0
    }, 16);

    /* ---- 2. Morello ret c30 ---- */
    run_test("ret_c30", (uint32_t[]){
        0xd2800540, 0xc2c253c0
    }, 8);

    /* ---- 3. A64 movz (ALU immediate) ---- */
    run_test("movz_x0", (uint32_t[]){
        0xd2800540, 0xc2c253c0
    }, 8);

    /* ---- 4. A64 orr (ALU register) ---- */
    run_test("orr_x0_xzr_x1", (uint32_t[]){
        0xaa0103e0, 0xc2c253c0
    }, 8);

    /* ---- 5. A64 add (ALU register) ---- */
    run_test("add_x0_x1_x2", (uint32_t[]){
        0x8b020020, 0xc2c253c0
    }, 8);

    /* ---- 6. A64 sub (ALU register) ---- */
    run_test("sub_x0_x1_x2", (uint32_t[]){
        0xcb020020, 0xc2c253c0
    }, 8);

    /* ---- 7. A64 b (branch) ---- */
    run_test("b_forward", (uint32_t[]){
        0x14000001, 0xd2800540, 0xc2c253c0
    }, 12);

    /* ---- 8. A64 bl (branch with link) ---- */
    run_test("bl_forward", (uint32_t[]){
        0x94000001, 0xd2800540, 0xc2c253c0
    }, 12);

    /* ---- 9. A64 str x5, [x19] (store through X reg to separate RW page) ---- */
    run_test("str_x5_x19_sep_page", (uint32_t[]){
        movz, movk16, movk32, 0xd2800545, 0xf9000265, 0xd2800000, 0xc2c253c0
    }, 28);

    /* ---- 10. A64 stur x5, [x19, #-8] (store with negative offset) ---- */
    run_test("stur_x5_x19_neg8", (uint32_t[]){
        movz, movk16, movk32, 0xd2800545, 0xf81f8265, 0xd2800000, 0xc2c253c0
    }, 28);

    /* ---- 11. A64 str x5, [sp] (store through SP to native stack) ---- */
    run_test("str_x5_sp", (uint32_t[]){
        0xd2800545, 0xf90003e5, 0xd2800000, 0xc2c253c0
    }, 16);

    /* ---- 12. A64 ldr x5, [x19] (load through X reg from separate RW page) ---- */
    run_test("ldr_x5_x19_sep_page", (uint32_t[]){
        movz, movk16, movk32, 0xf9400265, 0xaa0503e0, 0xc2c253c0
    }, 24);

    /* ---- 13. Morello str c30, [c0] (capability store through C reg) ---- */
    run_test("str_c30_c0", (uint32_t[]){
        0xc200001e, 0xd2800000, 0xc2c253c0
    }, 12);

    /* ---- 14. Morello ldr c30, [c0] (capability load through C reg) ---- */
    run_test("ldr_c30_c0", (uint32_t[]){
        0xc240001e, 0xd2800000, 0xc2c253c0
    }, 12);

    /* ---- 15. mprotect from JIT: NOT tested (would need a syscall) ---- */
    printf("  mprotect_from_jit: skipped (requires syscall)\n");

    printf("\n=== Matrix Complete ===\n");
    return 0;
}
