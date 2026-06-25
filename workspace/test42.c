#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include "ubpf.h"
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    uint8_t prog[] = {0xb7,0,0,0,0x2a,0,0,0, 0x95,0,0,0,0,0,0,0};
    /* Test: interpreter */
    struct ubpf_vm *vm = ubpf_create();
    char *e = NULL;
    ubpf_load(vm, prog, sizeof(prog), &e);
    uint64_t r;
    int rc = ubpf_exec(vm, NULL, 0, &r);
    printf("interp rc=%d r0=%llu\n", rc, (unsigned long long)r);
    ubpf_destroy(vm);
    /* Test: CHERI JIT in fork */
    pid_t p = fork();
    if (p == 0) {
        vm = ubpf_create();
        ubpf_load(vm, prog, sizeof(prog), &e);
        ubpf_jit_fn j = ubpf_compile(vm, &e);
        if (!j) {printf("compile failed: %s\n", e); _exit(1);}
        r = j(NULL, 0);
        printf("cheri_jit r0=%llu\n", (unsigned long long)r);
        _exit(0);
    }
    int s; waitpid(p, &s, 0);
    if (WIFSIGNALED(s)) printf("cheri_jit crash: signal %d\n", WTERMSIG(s));
    else printf("cheri_jit exit: %d\n", WEXITSTATUS(s));
    return 0;
}
