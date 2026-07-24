#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ubpf.h"

#define INSN(op, dst, src, off, imm) \
    (uint8_t)(op), (uint8_t)(((dst) & 0xf) | (((src) & 0xf) << 4)), \
    (uint8_t)((off) & 0xff), (uint8_t)(((off) >> 8) & 0xff), \
    (uint8_t)((imm) & 0xff), (uint8_t)(((imm) >> 8) & 0xff), \
    (uint8_t)(((imm) >> 16) & 0xff), (uint8_t)(((imm) >> 24) & 0xff)

#define R0 0
#define R2 2
#define R6 6

#define HELPER_MAP_LOOKUP 7
#define HOST_MAP_LOGICAL_BYTES 16
#define HOST_MAP_BACKING_BYTES 8192
#define HOST_OOB_SENTINEL 0xfeedfacecafebeefULL


extern void ubpf_cheri_set_map_value_helper_index(struct ubpf_vm* vm, int index);

enum expectation {
    EXPECT_RETURN,
    EXPECT_TRAP,
};

struct helper_map_case {
    const char* name;
    const char* coverage;
    const uint8_t* code;
    size_t code_len;
    enum expectation expectation;
    uint64_t expected;
};

struct run_outcome {
    int returned;
    int signalled;
    int signal;
    int exit_status;
    uint64_t value;
};

static volatile sig_atomic_t expect_signal_trap;

static const uint8_t helper_map_read_in_bounds[] = {
    INSN(0x85, 0, 0, 0, HELPER_MAP_LOOKUP),
    INSN(0xbf, R6, R0, 0, 0),
    INSN(0x79, R0, R6, 8, 0),
    INSN(0x95, 0, 0, 0, 0),
};

static const uint8_t helper_map_write_in_bounds[] = {
    INSN(0x85, 0, 0, 0, HELPER_MAP_LOOKUP),
    INSN(0xbf, R6, R0, 0, 0),
    INSN(0xb7, R2, 0, 0, 0x5a),
    INSN(0x7b, R6, R2, 8, 0),
    INSN(0x79, R0, R6, 8, 0),
    INSN(0x95, 0, 0, 0, 0),
};

static const uint8_t helper_map_read_oob[] = {
    INSN(0x85, 0, 0, 0, HELPER_MAP_LOOKUP),
    INSN(0xbf, R6, R0, 0, 0),
    INSN(0x79, R0, R6, 4096, 0),
    INSN(0x95, 0, 0, 0, 0),
};

static const uint8_t helper_map_write_oob[] = {
    INSN(0x85, 0, 0, 0, HELPER_MAP_LOOKUP),
    INSN(0xbf, R6, R0, 0, 0),
    INSN(0xb7, R2, 0, 0, 0x5a),
    INSN(0x7b, R6, R2, 4096, 0),
    INSN(0xb7, R0, 0, 0, 0),
    INSN(0x95, 0, 0, 0, 0),
};

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
#ifdef SIGPROT
    case SIGPROT:
        return "SIGPROT";
#endif
    default:
        return "signal";
    }
}

#if defined(__CHERI_PURE_CAPABILITY__)
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
        _exit(expect_signal_trap ? 100 : 31);
    }
#endif
    printf("  trapped: signal=%d code=%d address=%p\n",
        signo,
        info ? info->si_code : -1,
        info ? info->si_addr : NULL);
    _exit(expect_signal_trap ? 100 : 31);
}

static void
install_trap_handlers(enum expectation expectation)
{
    expect_signal_trap = expectation == EXPECT_TRAP;

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

#endif

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
prepare_map(uint8_t* map, size_t len)
{
    memset(map, 0, len);
    uint64_t* words = (uint64_t*)map;
    words[0] = 0x1000ULL;
    words[1] = 0x2000ULL;
    if (len >= 4096 + sizeof(uint64_t)) {
        words[512] = HOST_OOB_SENTINEL;
    }
}

static int
load_compile_and_call(const struct helper_map_case* test_case, int pipefd)
{
#if defined(__CHERI_PURE_CAPABILITY__)
    uint64_t map[2];
    prepare_map((uint8_t*)map, sizeof(map));
    void* mem = map;
    size_t mem_len = sizeof(map);
#else
    uint8_t map[HOST_MAP_BACKING_BYTES];
    prepare_map(map, sizeof(map));
    void* mem = map;
    size_t mem_len = HOST_MAP_LOGICAL_BYTES;
#endif

    struct ubpf_vm* vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "ubpf_create failed\n");
        return 2;
    }

    ubpf_cheri_set_map_value_helper_index(vm, HELPER_MAP_LOOKUP);
    if (ubpf_register(vm, HELPER_MAP_LOOKUP, "map_lookup_value", as_external_function_t(map_lookup_helper)) != 0) {
        fprintf(stderr, "ubpf_register failed\n");
        ubpf_destroy(vm);
        return 2;
    }

    char* errmsg = NULL;
    if (ubpf_load(vm, test_case->code, (uint32_t)test_case->code_len, &errmsg) != 0) {
        fprintf(stderr, "ubpf_load failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        return 3;
    }

    ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
    if (!fn) {
        fprintf(stderr, "ubpf_compile failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        return 4;
    }

    uint64_t result = fn(mem, mem_len);
    if (write_all(pipefd, &result, sizeof(result)) != 0) {
        ubpf_destroy(vm);
        return 5;
    }

    ubpf_destroy(vm);
    return 0;
}

static struct run_outcome
run_case_child(const struct helper_map_case* test_case)
{
    struct run_outcome outcome = {0};
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        outcome.exit_status = 90;
        return outcome;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        outcome.exit_status = 91;
        return outcome;
    }

    if (pid == 0) {
        close(pipefd[0]);
#if defined(__CHERI_PURE_CAPABILITY__)
        install_trap_handlers(test_case->expectation);
#endif
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
        outcome.exit_status = 92;
        return outcome;
    }

    if (WIFSIGNALED(status)) {
        outcome.signalled = 1;
        outcome.signal = WTERMSIG(status);
        return outcome;
    }

    outcome.exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 93;
    if (outcome.exit_status == 100) {
        outcome.signalled = 1;
#ifdef SIGPROT
        outcome.signal = SIGPROT;
#else
        outcome.signal = 0;
#endif
        return outcome;
    }
    if (outcome.exit_status == 0 && n == (ssize_t)sizeof(value)) {
        outcome.returned = 1;
        outcome.value = value;
    }
    return outcome;
}

static int
case_passed(const struct helper_map_case* test_case, const struct run_outcome* outcome)
{
#if defined(__CHERI_PURE_CAPABILITY__)
    if (test_case->expectation == EXPECT_TRAP) {
        return outcome->signalled && outcome->signal == SIGPROT;
    }
    return outcome->returned && outcome->value == test_case->expected;
#else
    if (test_case->expectation == EXPECT_TRAP) {
        return outcome->returned || outcome->signalled;
    }
    return outcome->returned && outcome->value == test_case->expected;
#endif
}

static void
print_outcome(const struct run_outcome* outcome)
{
    if (outcome->returned) {
        printf("returned 0x%" PRIx64, outcome->value);
    } else if (outcome->signalled) {
        printf("trapped with %s/%d", signal_name(outcome->signal), outcome->signal);
    } else {
        printf("error exit=%d", outcome->exit_status);
    }
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

#if defined(__CHERI_PURE_CAPABILITY__)
    printf("helper-returned map capability CHERI JIT suite\n");
#else
    printf("helper-returned map pointer host/x86_64 JIT baseline\n");
    printf("logical map bytes: %d\n", HOST_MAP_LOGICAL_BYTES);
    printf("host backing bytes: %d\n", HOST_MAP_BACKING_BYTES);
    printf("oob sentinel: 0x%" PRIx64 "\n", (uint64_t)HOST_OOB_SENTINEL);
#endif

    const struct helper_map_case cases[] = {
        {
            "helper_map_read_in_bounds",
            "helper-returned map-value root, in-bounds read",
            helper_map_read_in_bounds,
            sizeof(helper_map_read_in_bounds),
            EXPECT_RETURN,
            0x2000ULL,
        },
        {
            "helper_map_write_in_bounds",
            "helper-returned map-value root, in-bounds write/read",
            helper_map_write_in_bounds,
            sizeof(helper_map_write_in_bounds),
            EXPECT_RETURN,
            0x5aULL,
        },
        {
            "helper_map_read_oob",
            "CVE-2021-4204-style helper/map OOB read analogue",
            helper_map_read_oob,
            sizeof(helper_map_read_oob),
            EXPECT_TRAP,
            0,
        },
        {
            "helper_map_write_oob",
            "CVE-2021-4204-style helper/map OOB write analogue",
            helper_map_write_oob,
            sizeof(helper_map_write_oob),
            EXPECT_TRAP,
            0,
        },
    };

    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const struct helper_map_case* test_case = &cases[i];

        printf("\n[helper map capability: %s]\n", test_case->name);
        printf("  coverage: %s\n", test_case->coverage);

        struct run_outcome outcome = run_case_child(test_case);
        int ok = case_passed(test_case, &outcome);

        printf("  outcome:  ");
        print_outcome(&outcome);
        printf("\n");
#if defined(__CHERI_PURE_CAPABILITY__)
        printf("  verdict:  %s\n", ok ? "CHERI behavior matched" : "unexpected CHERI behavior");
#else
        if (test_case->expectation == EXPECT_TRAP && outcome.returned) {
            printf("  verdict:  unsafe helper/map access executed under non-capability JIT\n");
        } else {
            printf("  verdict:  %s\n", ok ? "host baseline recorded" : "unexpected host behavior");
        }
#endif
        failures += ok ? 0 : 1;
    }

    if (failures) {
        printf("\nFAIL helper map capability cases failed: %d\n", failures);
        return 1;
    }

    printf("\nOK helper map capability suite passed\n");
    return 0;
}
