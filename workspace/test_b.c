#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Test: b (branch, no link) from mmap */
    {
        /* b +2 (skip nop, land on mov) */
        uint32_t code[] = {
            0x028083f0,  /* sub csp, csp, #32 */
            0x14000002,  /* b +2 (skip next 2 insns) ... actually +2 means skip 2 */
            0xd503201f,  /* nop (skipped) */
            0xd503201f,  /* nop (skipped) */
            0xd2800540,  /* mov x0, #42 */
            0x020083f0,  /* add csp, csp, #32 */
            0xc2c253c0,  /* ret c30 */
        };
        void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { perror("mmap"); return 1; }
        memcpy(p, code, sizeof(code));
        pid_t pid = fork();
        if (pid == 0) {
            uint64_t r = ((uint64_t(*)(void*,size_t))p)(NULL, 0);
            printf("test_b (sub+b+nop+mov+add+ret): r0=%llu\n", (unsigned long long)r);
            _exit(0);
        }
        int s; waitpid(pid, &s, 0);
        if (WIFSIGNALED(s)) printf("test_b CRASH sig %d\n", WTERMSIG(s));
    }

    return 0;
}
