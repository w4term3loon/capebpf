#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void *data_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    /* Test A: A64 data store str x5, [x0] through C0 (tagged cap)
     * str x5, [x0, #0] encoding:
     *   11111001 00 imm12(0) Rn(0) Rt(5) = 0xf90000a5
     * Wait: Rn=0, Rt=5: 0xf9000000 | (0 << 5) | 5 = 0xf9000005
     * Actually: 0xf9000000 | (0 << 10) | (0 << 5) | 5 = 0xf9000005
     */
    uint32_t code_a[] = {
        0xd2800545,  /* movz x5, #42 */
        0xf9000005,  /* str x5, [x0, #0] — A64 data store through C0 */
        0xd2800000,  /* movz x0, #0 */
        0xc2c253c0,  /* ret c30 */
    };

    /* Test B: Morello str c30, [c0, #0] — capability store through C0 */
    uint32_t code_b[] = {
        0xc200001e,  /* str c30, [c0, #0] */
        0xd2800000,  /* movz x0, #0 */
        0xc2c253c0,  /* ret c30 */
    };

    /* Test C: A64 ldr x5, [x0] — A64 data load through C0 */
    uint32_t code_c[] = {
        0xf9400005,  /* ldr x5, [x0, #0] */
        0xaa0503e0,  /* mov x0, x5 */
        0xc2c253c0,  /* ret c30 */
    };

    void *jit = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    /* Run test A */
    memcpy(jit, code_a, sizeof(code_a));
    printf("Test A: str x5, [x0] through tagged C0\n");
    {
        pid_t p = fork();
        if (p == 0) {
            uint64_t r = ((uint64_t(*)(void * __capability))jit)(data_page);
            printf("  OK: r0=%llu data[0]=%d\n", (unsigned long long)r, ((uint8_t*)data_page)[0]);
            _exit(0);
        }
        int s; waitpid(p, &s, 0);
        if (WIFSIGNALED(s)) printf("  CRASH sig %d\n", WTERMSIG(s));
    }

    /* Run test B */
    memcpy(jit, code_b, sizeof(code_b));
    printf("Test B: str c30, [c0] through tagged C0\n");
    {
        pid_t p = fork();
        if (p == 0) {
            uint64_t r = ((uint64_t(*)(void * __capability))jit)(data_page);
            printf("  OK: r0=%llu\n", (unsigned long long)r);
            _exit(0);
        }
        int s; waitpid(p, &s, 0);
        if (WIFSIGNALED(s)) printf("  CRASH sig %d\n", WTERMSIG(s));
    }

    /* Run test C: write 42 to data_page first, then load from JIT */
    ((uint64_t*)data_page)[0] = 42;
    memcpy(jit, code_c, sizeof(code_c));
    printf("Test C: ldr x5, [x0] through tagged C0 (data_page has 42)\n");
    {
        pid_t p = fork();
        if (p == 0) {
            uint64_t r = ((uint64_t(*)(void * __capability))jit)(data_page);
            printf("  OK: r0=%llu (expect 42)\n", (unsigned long long)r);
            _exit(0);
        }
        int s; waitpid(p, &s, 0);
        if (WIFSIGNALED(s)) printf("  CRASH sig %d\n", WTERMSIG(s));
    }

    return 0;
}
