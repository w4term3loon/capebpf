#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Test 1: Just sub csp + mov + add csp + ret c30 (known working PoC) */
    {
        uint32_t code[] = {
            0x028083f0, 0xd2800540, 0x020083f0, 0xc2c253c0,
        };
        void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { perror("mmap"); return 1; }
        memcpy(p, code, sizeof(code));
        pid_t pid = fork();
        if (pid == 0) {
            uint64_t r = ((uint64_t(*)(void*,size_t))p)(NULL, 0);
            printf("test1 (PoC): r0=%llu\n", (unsigned long long)r);
            _exit(0);
        }
        int s; waitpid(pid, &s, 0);
        if (WIFSIGNALED(s)) printf("test1 CRASH sig %d\n", WTERMSIG(s));
    }

    /* Test 2: PoC + orr x26,xzr,x0 */
    {
        uint32_t code[] = {
            0x028083f0,  /* sub csp, csp, #32 */
            0x2a0003fa,  /* orr x26, xzr, x0 */
            0xd2800540,  /* mov x0, #42 */
            0x020083f0,  /* add csp, csp, #32 */
            0xc2c253c0,  /* ret c30 */
        };
        void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        memcpy(p, code, sizeof(code));
        pid_t pid = fork();
        if (pid == 0) {
            uint64_t r = ((uint64_t(*)(void*,size_t))p)(NULL, 0);
            printf("test2 (PoC+orr): r0=%llu\n", (unsigned long long)r);
            _exit(0);
        }
        int s; waitpid(pid, &s, 0);
        if (WIFSIGNALED(s)) printf("test2 CRASH sig %d\n", WTERMSIG(s));
    }

    /* Test 3: PoC + bl + b */
    {
        /* bl +2 (skips next nop), nop, mov, add, ret */
        uint32_t code[] = {
            0x028083f0,  /* sub csp, csp, #32 */
            0x94000002,  /* bl +2 (skip nop, land on mov) */
            0xd503201f,  /* nop (skipped) */
            0xd2800540,  /* mov x0, #42 */
            0x020083f0,  /* add csp, csp, #32 */
            0xc2c253c0,  /* ret c30 */
        };
        void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        memcpy(p, code, sizeof(code));
        pid_t pid = fork();
        if (pid == 0) {
            uint64_t r = ((uint64_t(*)(void*,size_t))p)(NULL, 0);
            printf("test3 (PoC+bl): r0=%llu\n", (unsigned long long)r);
            _exit(0);
        }
        int s; waitpid(pid, &s, 0);
        if (WIFSIGNALED(s)) printf("test3 CRASH sig %d\n", WTERMSIG(s));
    }

    /* Test 4: sub csp, csp, #4096 (split: 4095 + 1) */
    {
        uint32_t code[] = {
            0x028ff7f0,  /* sub csp, csp, #4095 */
            0x028003f0,  /* sub csp, csp, #1 */
            0xd2800540,  /* mov x0, #42 */
            0x028ff7f0,  /* add csp, csp, #4095 */
            0x020003f0,  /* add csp, csp, #1 */
            0xc2c253c0,  /* ret c30 */
        };
        void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        memcpy(p, code, sizeof(code));
        pid_t pid = fork();
        if (pid == 0) {
            uint64_t r = ((uint64_t(*)(void*,size_t))p)(NULL, 0);
            printf("test4 (sub4096 split): r0=%llu\n", (unsigned long long)r);
            _exit(0);
        }
        int s; waitpid(pid, &s, 0);
        if (WIFSIGNALED(s)) printf("test4 CRASH sig %d\n", WTERMSIG(s));
    }

    return 0;
}
