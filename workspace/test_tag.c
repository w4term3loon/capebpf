#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Allocate a SEPARATE RW page as a tagged capability (via mmap) */
    void *data_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    /* JIT code: store C30 (return capability) through C0 (arg = data_page cap)
     * str c30, [c0, #0]  →  0xc200001e
     * movz x0, #0         →  0xd2800000
     * ret c30              →  0xc2c253c0
     */
    uint32_t code[] = {
        0xc200001e,  /* str c30, [c0, #0] — store through C0 (tagged cap!) */
        0xd2800000,  /* movz x0, #0 */
        0xc2c253c0,  /* ret c30 */
    };

    void *jit_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(jit_page, code, sizeof(code));

    printf("data_page=%p (tagged capability)\n", data_page);
    printf("data[0..15] before: ");
    for (int i = 0; i < 16; i++) printf("%02x ", ((uint8_t*)data_page)[i]);
    printf("\n");

    /* Pass data_page as the FIRST ARGUMENT — on purecap this goes in C0
     * as a properly tagged capability pointer */
    pid_t pid = fork();
    if (pid == 0) {
        uint64_t r = ((uint64_t(*)(void * __capability))jit_page)(data_page);
        printf("JIT returned: %llu\n", (unsigned long long)r);
        printf("data[0..15] after:  ");
        for (int i = 0; i < 16; i++) printf("%02x ", ((uint8_t*)data_page)[i]);
        printf("\n");
        _exit(0);
    }
    int s; waitpid(pid, &s, 0);
    if (WIFSIGNALED(s))
        printf("JIT CRASHED signal %d\n", WTERMSIG(s));
    else if (((uint8_t*)data_page)[0] != 0)
        printf("STORE SUCCEEDED — data was written!\n");
    else
        printf("STORE FAILED — data unchanged\n");

    return 0;
}
