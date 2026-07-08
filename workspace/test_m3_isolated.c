#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Allocate a SEPARATE RW page (not executable) for data.
     * Load its address into X19 via movz/movk (integer immediate).
     * Then from JIT code (in an mmap RWX page), store to [X19+8].
     * If this works, A64 data stores through non-SP registers from JIT
     * memory succeed. If it crashes, ALL stores from mmap RWX fail. */

    /* Allocate data page */
    uint8_t *data_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (data_page == (void*)-1) { perror("data mmap"); return 1; }
    uint64_t data_addr = (uint64_t)data_page;

    /* Build JIT code that:
     * 1. movz x19, #<low16>; movk x19, #<mid16>, lsl #16; movk x19, #<high16>, lsl #32
     *    (load data_page address into x19)
     * 2. movz x5, #0x42 (value to store)
     * 3. str x5, [x19]  (store to data page via x19 through DDC)
     * 4. movz x0, #0    (return value)
     * 5. ret c30        (Morello return)
     *
     * A64 STR X5, [X19] encoding:
     *   base = 0xf9000000 | (0 << 10) | (19 << 5) | 5
     *   = 0xf9000265
     */
    uint32_t movz_x19_lo = 0xd2800000 | ((data_addr & 0xffff) << 5) | 19;
    uint32_t movk_x19_mid = 0xf2a00000 | (((data_addr >> 16) & 0xffff) << 5) | 19;
    uint32_t movk_x19_hi = 0xf2c00000 | (((data_addr >> 32) & 0xffff) << 5) | 19;

    uint32_t code[] = {
        movz_x19_lo,       /* movz x19, #<lo16> */
        movk_x19_mid,      /* movk x19, #<mid16>, lsl #16 */
        movk_x19_hi,      /* movk x19, #<hi16>, lsl #32 */
        0xd2800545,        /* movz x5, #42 */
        0xf9000265,        /* str x5, [x19] (store through X19 via DDC) */
        0xd2800000,        /* movz x0, #0 */
        0xc2c253c0,        /* ret c30 */
    };

    void *jit_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (jit_page == (void*)-1) { perror("jit mmap"); return 1; }
    memcpy(jit_page, code, sizeof(code));

    printf("data_page=%p addr=0x%llx\n", data_page, (unsigned long long)data_addr);
    printf("data[0..7] before: ");
    for (int i = 0; i < 8; i++) printf("%02x ", data_page[i]);
    printf("\n");

    pid_t pid = fork();
    if (pid == 0) {
        uint64_t r = ((uint64_t(*)(void*,size_t))jit_page)(NULL, 0);
        printf("JIT returned: %llu\n", (unsigned long long)r);
        printf("data[0..7] after:  ");
        for (int i = 0; i < 8; i++) printf("%02x ", data_page[i]);
        printf("\n");
        _exit(0);
    }
    int s; waitpid(pid, &s, 0);
    if (WIFSIGNALED(s))
        printf("JIT CRASHED signal %d\n", WTERMSIG(s));
    else if (data_page[0] == 42 && data_page[1] == 0)
        printf("STORE SUCCEEDED — data[0]=%d\n", data_page[0]);
    else
        printf("STORE FAILED — data unchanged or wrong\n");

    return 0;
}
