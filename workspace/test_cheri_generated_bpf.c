#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ubpf.h"

#define BPF_OBJECT(name) "/mnt/bpf/" name ".o"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum generated_bpf_expectation {
    EXPECT_RETURN,
    EXPECT_CHERI_TRAP,
};

struct generated_bpf_case {
    const char* name;
    const char* object_path;
    const char* symbol;
    uint64_t expected_result;
    enum generated_bpf_expectation expectation;
};

static volatile sig_atomic_t expect_signal_trap;

static const char*
expectation_label(enum generated_bpf_expectation expectation)
{
    return expectation == EXPECT_CHERI_TRAP ? "expect CHERI trap" : "expect return value";
}

static void*
read_file(const char* path, size_t* len)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        perror(path);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        return NULL;
    }

    long size = ftell(fp);
    if (size < 0) {
        perror("ftell");
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    void* data = malloc((size_t)size);
    if (!data) {
        fclose(fp);
        return NULL;
    }

    if (fread(data, 1, (size_t)size, fp) != (size_t)size) {
        perror("fread");
        free(data);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    *len = (size_t)size;
    return data;
}

static void
trap_handler(int signo, siginfo_t* info, void* uctx)
{
    (void)uctx;
    printf("  trapped: signal=%d code=%d address=%p\n",
        signo,
        info ? info->si_code : -1,
        info ? info->si_addr : NULL);
    _exit(expect_signal_trap ? 0 : 31);
}

static void
install_trap_handlers(enum generated_bpf_expectation expectation)
{
    expect_signal_trap = expectation == EXPECT_CHERI_TRAP;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = trap_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

#ifdef SIGPROT
    if (sigaction(SIGPROT, &sa, NULL) != 0) {
        perror("sigaction(SIGPROT)");
        _exit(11);
    }
#endif
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        perror("sigaction(SIGSEGV)");
        _exit(11);
    }
}

static int
load_compile_and_call(const struct generated_bpf_case* test_case)
{
    size_t elf_len = 0;
    void* elf = read_file(test_case->object_path, &elf_len);
    if (!elf) {
        return 2;
    }

    struct ubpf_vm* vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "ubpf_create failed\n");
        free(elf);
        return 2;
    }

    char* errmsg = NULL;
    if (ubpf_load_elf_ex(vm, elf, elf_len, test_case->symbol, &errmsg) < 0) {
        fprintf(stderr, "ubpf_load_elf_ex failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        free(elf);
        return 1;
    }

    ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
    if (!fn) {
        fprintf(stderr, "ubpf_compile failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        free(elf);
        return 1;
    }

    uint64_t ctx[] = {0x1000ULL, 0x2000ULL};
    uint64_t result = fn(ctx, sizeof(ctx));
    printf("  returned: 0x%" PRIx64 "\n", result);
    printf("  expected: 0x%" PRIx64 "\n", test_case->expected_result);

    ubpf_destroy(vm);
    free(elf);

    if (test_case->expectation == EXPECT_CHERI_TRAP) {
        printf("  expected a trap, but execution returned\n");
        return 20;
    }
    return result == test_case->expected_result ? 0 : 21;
}

static int
run_case(const struct generated_bpf_case* test_case)
{
    printf("\n[generated BPF CHERI JIT: %s]\n", test_case->name);
    printf("  object:   %s\n", test_case->object_path);
    printf("  symbol:   %s\n", test_case->symbol);
    printf("  outcome:  %s\n", expectation_label(test_case->expectation));

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        install_trap_handlers(test_case->expectation);
        _exit(load_compile_and_call(test_case));
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        printf("  parent: child terminated by signal %d\n", sig);
        return test_case->expectation == EXPECT_CHERI_TRAP ? 0 : 1;
    }

    int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    printf("  parent: child exit=%d\n", exit_status);
    return exit_status == 0 ? 0 : 1;
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("generated BPF CHERI JIT test suite\n");

    const struct generated_bpf_case cases[] = {
        {"stack_array", BPF_OBJECT("stack_array"), "foo", 0x6aULL, EXPECT_RETURN},
        {"branch_stack", BPF_OBJECT("branch_stack"), "foo", 0x24ULL, EXPECT_RETURN},
        {"stack_widths", BPF_OBJECT("stack_widths"), "foo", 0x64ULL, EXPECT_RETURN},
        {"context_in_bounds", BPF_OBJECT("context_in_bounds"), "foo", 0x3000ULL, EXPECT_RETURN},
        {"branch_context_in_bounds", BPF_OBJECT("branch_context_in_bounds"), "foo", 0x2000ULL, EXPECT_RETURN},
        {"arithmetic_context_in_bounds", BPF_OBJECT("arithmetic_context_in_bounds"), "foo", 0x2000ULL, EXPECT_RETURN},
        {"context_oob", BPF_OBJECT("context_oob"), "foo", 0, EXPECT_CHERI_TRAP},
        {"branch_context_oob", BPF_OBJECT("branch_context_oob"), "foo", 0, EXPECT_CHERI_TRAP},
        {"arithmetic_context_oob", BPF_OBJECT("arithmetic_context_oob"), "foo", 0, EXPECT_CHERI_TRAP},
        {"stack_oob", BPF_OBJECT("stack_oob"), "foo", 0, EXPECT_CHERI_TRAP},
    };

    int failures = 0;
    for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
        failures += run_case(&cases[i]);
    }

    if (failures) {
        printf("\nFAIL generated BPF CHERI JIT cases failed: %d\n", failures);
        return 1;
    }

    printf("\nOK generated BPF CHERI JIT suite passed\n");
    return 0;
}
