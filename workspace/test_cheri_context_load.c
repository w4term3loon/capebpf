#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ubpf.h"

#define INSN(op, dst, src, off, imm) \
    (uint8_t)(op), (uint8_t)((dst) | ((src) << 4)), \
    (uint8_t)((off) & 0xff), (uint8_t)(((off) >> 8) & 0xff), \
    (uint8_t)((imm) & 0xff), (uint8_t)(((imm) >> 8) & 0xff), \
    (uint8_t)(((imm) >> 16) & 0xff), (uint8_t)(((imm) >> 24) & 0xff)

static ubpf_jit_fn
compile_program(const uint8_t *prog, size_t prog_len)
{
    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "ubpf_create failed\n");
        return NULL;
    }

    char *errmsg = NULL;
    if (ubpf_load(vm, prog, (uint32_t)prog_len, &errmsg) != 0) {
        fprintf(stderr, "load failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        return NULL;
    }

    ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
    if (!fn) {
        fprintf(stderr, "compile failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        return NULL;
    }

    return fn;
}

static int
run_child_and_wait(const char *name, int (*child_fn)(void))
{
    pid_t pid = fork();
    if (pid == 0) {
        _exit(child_fn());
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFSIGNALED(status)) {
        printf("FAIL %s: trapped with signal %d\n", name, WTERMSIG(status));
        return 1;
    }

    int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    if (exit_status != 0) {
        printf("FAIL %s: child exit=%d\n", name, exit_status);
        return 1;
    }

    return 0;
}

static int
run_in_bounds_context_load(void)
{
    uint8_t prog[] = {
        INSN(0x79, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint64_t mem[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
    ubpf_jit_fn fn = compile_program(prog, sizeof(prog));
    if (!fn) {
        return 1;
    }

    uint64_t result = fn(mem, sizeof(mem));
    if (result != mem[1]) {
        printf("FAIL context_in_bounds: r0=0x%llx expected=0x%llx\n",
            (unsigned long long)result,
            (unsigned long long)mem[1]);
        return 1;
    }

    printf("OK   context_in_bounds: r0=0x%llx\n", (unsigned long long)result);
    return 0;
}

static int
test_in_bounds_context_load(void)
{
    return run_child_and_wait("context_in_bounds", run_in_bounds_context_load);
}

static int
test_oob_context_load_faults(void)
{
    uint8_t prog[] = {
        INSN(0x79, 0, 1, 4096, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint64_t mem[] = {0x1111111111111111ULL, 0x2222222222222222ULL};
    ubpf_jit_fn fn = compile_program(prog, sizeof(prog));
    if (!fn) {
        return 1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        uint64_t result = fn(mem, sizeof(mem));
        printf("FAIL context_oob: returned 0x%llx\n", (unsigned long long)result);
        _exit(2);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFSIGNALED(status)) {
        printf("OK   context_oob: trapped with signal %d\n", WTERMSIG(status));
        return 0;
    }

    printf("FAIL context_oob: child exit=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int failures = 0;
    failures += test_in_bounds_context_load();
    failures += test_oob_context_load_faults();
    return failures == 0 ? 0 : 1;
}
