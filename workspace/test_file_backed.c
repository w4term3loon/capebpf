#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void *data_page = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    /* Method 1: anonymous mmap RWX (known to crash on stores) */
    uint32_t code[] = {
        0xd2800545,  /* movz x5, #42 */
        0xf9000005,  /* str x5, [x0, #0] — store through C0 */
        0xd2800000,  /* movz x0, #0 */
        0xc2c253c0,  /* ret c30 */
    };

    /* Method 2: write to temp file, mmap as PROT_READ|PROT_EXEC */
    char tmpl[] = "/tmp/jit_test_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) { perror("mkstemp"); return 1; }
    write(fd, code, sizeof(code));
    /* Unlink the file so it goes away when we close fd */
    unlink(tmpl);

    void *jit_file = mmap(NULL, 4096, PROT_READ|PROT_EXEC,
                          MAP_PRIVATE, fd, 0);
    if (jit_file == (void*)-1) {
        printf("file mmap PROT_EXEC: FAILED (%s)\n", strerror(errno));
    } else {
        printf("file mmap PROT_EXEC: %p\n", jit_file);
        pid_t p = fork();
        if (p == 0) {
            uint64_t r = ((uint64_t(*)(void * __capability))jit_file)(data_page);
            printf("fileback JIT: returned %llu, page[0]=%llu\n",
                   (unsigned long long)r, (unsigned long long)*(uint64_t*)data_page);
            _exit(0);
        }
        int s; waitpid(p, &s, 0);
        if (WIFSIGNALED(s)) printf("fileback JIT: CRASH sig %d\n", WTERMSIG(s));
        else printf("fileback: page[0]=%llu\n", (unsigned long long)*(uint64_t*)data_page);
    }
    close(fd);

    /* Method 3: anonymous mmap as RW, write, then mprotect to RX */
    void *jit_rw = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (jit_rw == (void*)-1) { perror("mmap rw"); return 1; }
    memcpy(jit_rw, code, sizeof(code));
    int mrc = mprotect(jit_rw, 4096, PROT_READ|PROT_EXEC);
    printf("mprotect RW->RX: %s\n", mrc == 0 ? "OK" : strerror(errno));

    return 0;
}
