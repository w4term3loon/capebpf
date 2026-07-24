#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ubpf.h"
#define GENERATED_BPF_OBJECT_ROOT "/mnt/bpf/"
#include "generated_bpf_cases.h"

extern void ubpf_cheri_set_map_value_helper_index(struct ubpf_vm* vm, int index);

static volatile sig_atomic_t expect_signal_trap;

static const char*
expectation_label(enum generated_bpf_expectation expectation)
{
    return expectation == EXPECT_CHERI_TRAP ? "expect CHERI trap" : "expect return value";
}

static const char*
sigprot_code_name(int code)
{
    switch (code) {
#ifdef PROT_CHERI_BOUNDS
    case PROT_CHERI_BOUNDS:
        return "PROT_CHERI_BOUNDS";
#endif
#ifdef PROT_CHERI_TAG
    case PROT_CHERI_TAG:
        return "PROT_CHERI_TAG";
#endif
#ifdef PROT_CHERI_SEALED
    case PROT_CHERI_SEALED:
        return "PROT_CHERI_SEALED";
#endif
#ifdef PROT_CHERI_TYPE
    case PROT_CHERI_TYPE:
        return "PROT_CHERI_TYPE";
#endif
#ifdef PROT_CHERI_PERM
    case PROT_CHERI_PERM:
        return "PROT_CHERI_PERM";
#endif
#ifdef PROT_CHERI_IMPRECISE
    case PROT_CHERI_IMPRECISE:
        return "PROT_CHERI_IMPRECISE";
#endif
#ifdef PROT_CHERI_STORELOCAL
    case PROT_CHERI_STORELOCAL:
        return "PROT_CHERI_STORELOCAL";
#endif
#ifdef PROT_CHERI_CINVOKE
    case PROT_CHERI_CINVOKE:
        return "PROT_CHERI_CINVOKE";
#endif
#ifdef PROT_CHERI_SYSREG
    case PROT_CHERI_SYSREG:
        return "PROT_CHERI_SYSREG";
#endif
#ifdef PROT_CHERI_UNALIGNED_BASE
    case PROT_CHERI_UNALIGNED_BASE:
        return "PROT_CHERI_UNALIGNED_BASE";
#endif
    default:
        return "UNKNOWN";
    }
}

static uint64_t
map_lookup_helper(uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, void* ctx)
{
    (void)p0;
    (void)p1;
    (void)p2;
    (void)p3;
    (void)p4;
    return (uint64_t)(uintptr_t)ctx;
}

static void
prepare_words(uint64_t* words, size_t word_count)
{
    for (size_t i = 0; i < word_count; i++) {
        words[i] = 0;
    }
    words[0] = 0x1000ULL;
    words[1] = 0x2000ULL;
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
#ifdef SIGPROT
    if (signo == SIGPROT) {
        printf("  trapped: signal=%d code=%d(%s) trapno=%d capreg=%d address=%p\n",
            signo,
            info ? info->si_code : -1,
            info ? sigprot_code_name(info->si_code) : "<no-siginfo>",
            info ? info->si_trapno : -1,
            info ? info->si_capreg : -1,
            info ? info->si_addr : NULL);
        _exit(expect_signal_trap ? 0 : 31);
    }
#endif
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

    ubpf_cheri_set_map_value_helper_index(vm, GENERATED_BPF_HELPER_MAP_LOOKUP);
    if (ubpf_register(
            vm,
            GENERATED_BPF_HELPER_MAP_LOOKUP,
            GENERATED_BPF_HELPER_MAP_NAME,
            as_external_function_t(map_lookup_helper)) != 0) {
        fprintf(stderr, "ubpf_register failed\n");
        ubpf_destroy(vm);
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

    uint64_t ctx[2];
    uint64_t map[2];
    prepare_words(ctx, sizeof(ctx) / sizeof(ctx[0]));
    prepare_words(map, sizeof(map) / sizeof(map[0]));

    void* mem = ctx;
    size_t mem_len = sizeof(ctx);
    if (test_case->memory_root == GENERATED_ROOT_HELPER_MAP) {
        mem = map;
        mem_len = sizeof(map);
    }

    uint64_t result = fn(mem, mem_len);
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
    printf("  relevance: %s\n", test_case->cve_relevance);
    printf("  coverage: %s\n", test_case->coverage);
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

    int failures = 0;
    for (size_t i = 0; i < GENERATED_BPF_CASE_COUNT; i++) {
        failures += run_case(&generated_bpf_cases[i]);
    }

    if (failures) {
        printf("\nFAIL generated BPF CHERI JIT cases failed: %d\n", failures);
        return 1;
    }

    printf("\nOK generated BPF CHERI JIT suite passed\n");
    return 0;
}
