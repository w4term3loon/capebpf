#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ubpf.h"
#include "generated_bpf_cases.h"

#define HOST_CONTEXT_LOGICAL_BYTES 16
#define HOST_CONTEXT_BACKING_BYTES 8192
#define HOST_MAP_LOGICAL_BYTES 16
#define HOST_MAP_BACKING_BYTES 8192
#define HOST_OOB_SENTINEL 0xfeedfacecafebeefULL

enum host_outcome_kind {
    HOST_RETURNED,
    HOST_SIGNALLED,
    HOST_ERROR,
};

struct host_outcome {
    enum host_outcome_kind kind;
    uint64_t value;
    int signal;
    int exit_status;
};

static const char*
expectation_label(enum generated_bpf_expectation expectation)
{
    return expectation == EXPECT_CHERI_TRAP ? "expect unsafe baseline" : "expect return value";
}

static const char*
signal_name(int sig)
{
    switch (sig) {
    case SIGSEGV:
        return "SIGSEGV";
    case SIGBUS:
        return "SIGBUS";
    case SIGILL:
        return "SIGILL";
    default:
        return "signal";
    }
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

static int
write_all(int fd, const void* payload, size_t payload_len)
{
    const uint8_t* bytes = payload;
    size_t written = 0;
    while (written < payload_len) {
        ssize_t rc = write(fd, bytes + written, payload_len - written);
        if (rc <= 0) {
            return -1;
        }
        written += (size_t)rc;
    }
    return 0;
}

static void
prepare_words(uint8_t* backing, size_t len)
{
    memset(backing, 0, len);

    uint64_t* words = (uint64_t*)backing;
    words[0] = 0x1000ULL;
    words[1] = 0x2000ULL;
    if (len >= 4096 + sizeof(uint64_t)) {
        words[512] = HOST_OOB_SENTINEL;
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

static int
load_compile_and_call(const struct generated_bpf_case* test_case, int pipefd)
{
    uint8_t backing[HOST_CONTEXT_BACKING_BYTES];
    size_t logical_len = HOST_CONTEXT_LOGICAL_BYTES;
    if (test_case->memory_root == GENERATED_ROOT_HELPER_MAP) {
        logical_len = HOST_MAP_LOGICAL_BYTES;
    }
    prepare_words(backing, sizeof(backing));

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
        return 3;
    }

    ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
    if (!fn) {
        fprintf(stderr, "ubpf_compile failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        free(elf);
        return 4;
    }

    uint64_t result = fn(backing, logical_len);
    if (write_all(pipefd, &result, sizeof(result)) != 0) {
        ubpf_destroy(vm);
        free(elf);
        return 5;
    }

    ubpf_destroy(vm);
    free(elf);
    return 0;
}

static struct host_outcome
run_case_child(const struct generated_bpf_case* test_case)
{
    struct host_outcome outcome = {0};
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        outcome.kind = HOST_ERROR;
        outcome.exit_status = 90;
        return outcome;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        outcome.kind = HOST_ERROR;
        outcome.exit_status = 91;
        return outcome;
    }

    if (pid == 0) {
        close(pipefd[0]);
        int rc = load_compile_and_call(test_case, pipefd[1]);
        close(pipefd[1]);
        _exit(rc);
    }

    close(pipefd[1]);
    uint64_t value = 0;
    ssize_t n = read(pipefd[0], &value, sizeof(value));
    close(pipefd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        outcome.kind = HOST_ERROR;
        outcome.exit_status = 92;
        return outcome;
    }

    if (WIFSIGNALED(status)) {
        outcome.kind = HOST_SIGNALLED;
        outcome.signal = WTERMSIG(status);
        return outcome;
    }

    if (!WIFEXITED(status)) {
        outcome.kind = HOST_ERROR;
        outcome.exit_status = 93;
        return outcome;
    }

    outcome.exit_status = WEXITSTATUS(status);
    if (outcome.exit_status == 0 && n == (ssize_t)sizeof(value)) {
        outcome.kind = HOST_RETURNED;
        outcome.value = value;
        return outcome;
    }

    outcome.kind = HOST_ERROR;
    return outcome;
}

static int
host_outcome_matches(const struct generated_bpf_case* test_case, const struct host_outcome* outcome)
{
    if (test_case->expectation == EXPECT_RETURN) {
        return outcome->kind == HOST_RETURNED && outcome->value == test_case->expected_result;
    }

    return outcome->kind == HOST_RETURNED || outcome->kind == HOST_SIGNALLED;
}

static void
print_outcome(const struct host_outcome* outcome)
{
    switch (outcome->kind) {
    case HOST_RETURNED:
        printf("returned 0x%" PRIx64, outcome->value);
        return;
    case HOST_SIGNALLED:
        printf("terminated by %s/%d", signal_name(outcome->signal), outcome->signal);
        return;
    case HOST_ERROR:
        printf("error exit=%d", outcome->exit_status);
        return;
    }
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("generated BPF host/x86_64 JIT comparison baseline\n");
    printf("logical context bytes: %d\n", HOST_CONTEXT_LOGICAL_BYTES);
    printf("host backing bytes:    %d\n", HOST_CONTEXT_BACKING_BYTES);
    printf("logical map bytes:     %d\n", HOST_MAP_LOGICAL_BYTES);
    printf("oob sentinel:          0x%" PRIx64 "\n", (uint64_t)HOST_OOB_SENTINEL);
    printf("\n");

    int failures = 0;
    for (size_t i = 0; i < GENERATED_BPF_CASE_COUNT; i++) {
        const struct generated_bpf_case* test_case = &generated_bpf_cases[i];
        struct host_outcome outcome = run_case_child(test_case);
        int ok = host_outcome_matches(test_case, &outcome);

        printf("[generated BPF host JIT: %s]\n", test_case->name);
        printf("  relevance: %s\n", test_case->cve_relevance);
        printf("  coverage:  %s\n", test_case->coverage);
        printf("  outcome:   %s\n", expectation_label(test_case->expectation));
        printf("  host jit:  ");
        print_outcome(&outcome);
        printf("\n");

        if (test_case->expectation == EXPECT_CHERI_TRAP && outcome.kind == HOST_RETURNED) {
            printf("  verdict:   unsafe access executed under non-capability JIT\n");
        } else if (test_case->expectation == EXPECT_CHERI_TRAP && outcome.kind == HOST_SIGNALLED) {
            printf("  verdict:   non-capability JIT did not provide deterministic isolation\n");
        } else if (ok) {
            printf("  verdict:   valid program preserved\n");
        } else {
            printf("  verdict:   unexpected host result\n");
        }
        printf("\n");

        failures += ok ? 0 : 1;
    }

    if (failures) {
        printf("FAIL generated BPF host baseline unexpected results: %d\n", failures);
        return 1;
    }

    printf("OK generated BPF host baseline completed\n");
    return 0;
}
