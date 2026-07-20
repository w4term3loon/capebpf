/* Test: a compiled function in .text that stores through a reg.
 * This proves .text stores work fine.
 * Then we test calling that from JIT to compare. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

volatile uint64_t data_target = 0;

/* A compiled function in .text that stores through its argument */
void __attribute__((noinline)) compiled_store_test(void * __capability target) {
    *(volatile uint64_t*)target = 42;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("data_target addr=%p\n", &data_target);
    printf("data_target before=%llu\n", (unsigned long long)data_target);

    pid_t p = fork();
    if (p == 0) {
        compiled_store_test(&data_target);
        printf("compiled_store_test: data_target=%llu\n", (unsigned long long)data_target);
        _exit(0);
    }
    int s; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("compiled_store_test CRASH sig %d\n", WTERMSIG(s));
    else printf("data_target after=%llu\n", (unsigned long long)data_target);

    /* Now the same: JIT code that does str x5,[x0] to an mmap page. 
     * The mmap page returns a tagged capability. Pass it as arg. */
    void *mmap_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    printf("\nmmap_page addr=%p\n", mmap_page);

    /* Test: A64 store through C0 = mmap_page (tagged capability) */
    uint32_t code[] = {
        0xd2800545,  /* movz x5, #42 */
        0xf9000005,  /* str x5, [x0, #0] */
        0xd2800000,  /* movz x0, #0 */
        0xc2c253c0,  /* ret c30 */
    };
    void *jit = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(jit, code, sizeof(code));

    /* Test calling directly from .text compiler linkage */
    p = fork();
    if (p == 0) {
        uint64_t r = ((uint64_t(*)(void * __capability))jit)(mmap_page);
        printf("JIT str: returned %llu, page[0]=%llu\n",
               (unsigned long long)r, (unsigned long long)*(uint64_t*)mmap_page);
        _exit(0);
    }
    waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("JIT str CRASH sig %d\n", WTERMSIG(s));
    else printf("page[0]=%llu\n", (unsigned long long)*(uint64_t*)mmap_page);

    /* Try wrote via the compiled function to the mmap page */
    p = fork();
    if (p == 0) {
        compiled_store_test(mmap_page);
        printf("compiled_store to mmap_page: page[0]=%llu\n",
               (unsigned long long)*(uint64_t*)mmap_page);
        _exit(0);
    }
    waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("compiled_store to mmap_page CRASH sig %d\n", WTERMSIG(s));
    else printf("mmap_page[0]=%llu\n", (unsigned long long)*(uint64_t*)mmap_page);

    return 0;
}
