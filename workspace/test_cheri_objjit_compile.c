#include <cheriintrin.h>
#include <signal.h>
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

static volatile sig_atomic_t expect_sigprot;

static const char *
sigprot_code_name(int code)
{
    switch (code) {
    case PROT_CHERI_BOUNDS:
        return "PROT_CHERI_BOUNDS";
    case PROT_CHERI_TAG:
        return "PROT_CHERI_TAG";
    case PROT_CHERI_SEALED:
        return "PROT_CHERI_SEALED";
    case PROT_CHERI_TYPE:
        return "PROT_CHERI_TYPE";
    case PROT_CHERI_PERM:
        return "PROT_CHERI_PERM";
    default:
        return "UNKNOWN";
    }
}

static void
sigprot_handler(int signo, siginfo_t *info, void *uctx)
{
    (void)uctx;
    fprintf(stderr,
        "  SIGPROT detail       signo=%d si_code=%d(%s) si_trapno=%d si_capreg=%d si_addr=%p\n",
        signo,
        info ? info->si_code : -1,
        info ? sigprot_code_name(info->si_code) : "<no-siginfo>",
        info ? info->si_trapno : -1,
        info ? info->si_capreg : -1,
        info ? info->si_addr : NULL);
    _exit(expect_sigprot ? 0 : 31);
}

static void
install_sigprot_handler(int expect_trap)
{
    expect_sigprot = expect_trap;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigprot_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPROT, &sa, NULL) != 0) {
        perror("sigaction(SIGPROT)");
        _exit(11);
    }
}

static void
print_cap(const char *label, const void *cap)
{
    printf("  %-22s tag=%d sealed=%d sentry=%d addr=0x%zx base=0x%zx len=0x%zx perms=0x%zx flags=0x%zx\n",
        label,
        cheri_tag_get(cap),
        cheri_is_sealed(cap),
        cheri_is_sentry(cap),
        (size_t)cheri_address_get(cap),
        (size_t)cheri_base_get(cap),
        (size_t)cheri_length_get(cap),
        (size_t)cheri_perms_get(cap),
        (size_t)cheri_flags_get(cap));
}

static ubpf_jit_fn
compile_with_ubpf(const uint8_t *prog, size_t prog_len, struct ubpf_vm **out_vm)
{
    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "ubpf_create failed\n");
        return NULL;
    }

    char *errmsg = NULL;
    if (ubpf_load(vm, prog, (uint32_t)prog_len, &errmsg) != 0) {
        fprintf(stderr, "ubpf_load failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        return NULL;
    }

    ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
    if (!fn) {
        fprintf(stderr, "ubpf_compile failed: %s\n", errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        return NULL;
    }

    *out_vm = vm;
    return fn;
}

static int
wait_for_child(pid_t pid, int expect_trap)
{
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    if (WIFSIGNALED(status)) {
        printf("  parent: child trapped with signal %d\n", WTERMSIG(status));
        return expect_trap ? 0 : 1;
    }
    int exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 99;
    printf("  parent: child exit=%d\n", exit_status);
    if (expect_trap) {
        return exit_status == 20 ? 1 : 0;
    }
    return exit_status == 0 ? 0 : 1;
}

static int
run_compile_and_call(
    const char *name, const uint8_t *prog, size_t prog_len, uint64_t expected_result, int expect_trap)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        install_sigprot_handler(expect_trap);
        printf("\n[ubpf_compile CHERI direct-JIT %s]\n", name);
        uint64_t ctx[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
        print_cap("ctx arg", ctx);

        struct ubpf_vm *vm = NULL;
        ubpf_jit_fn fn = compile_with_ubpf(prog, prog_len, &vm);
        if (!fn) {
            _exit(10);
        }
        print_cap("compiled fn", (const void *)fn);
        uint64_t result = fn(ctx, sizeof(ctx));
        printf("  returned              0x%llx\n", (unsigned long long)result);
        int ok = result == expected_result;
        ubpf_destroy(vm);
        if (expect_trap) {
            _exit(20);
        }
        _exit(ok ? 0 : 21);
    }
    return wait_for_child(pid, expect_trap);
}

static int
expect_compile_reject(const char *name, const uint8_t *prog, size_t prog_len)
{
    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "ubpf_create failed\n");
        return 1;
    }

    char *errmsg = NULL;
    if (ubpf_load(vm, prog, (uint32_t)prog_len, &errmsg) != 0) {
        printf("FAIL %s: load rejected before compile: %s\n", name, errmsg ? errmsg : "<no error>");
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
    if (fn) {
        printf("FAIL %s: ubpf_compile unexpectedly accepted unsupported program\n", name);
        ubpf_destroy(vm);
        return 1;
    }

    int matched = errmsg &&
        (strstr(errmsg, "does not yet support memory opcode") ||
         strstr(errmsg, "tracked context or stack capabilities") ||
         strstr(errmsg, "tracked stack capabilities") ||
         strstr(errmsg, "does not allow storing a capability value") ||
         strstr(errmsg, "does not allow returning a capability value"));
    printf("%s %s: ubpf_compile rejected: %s\n",
        matched ? "OK  " : "FAIL", name, errmsg ? errmsg : "<no error>");
    free(errmsg);
    ubpf_destroy(vm);
    return matched ? 0 : 1;
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("integrated CHERI direct-JIT compile test: sizeof(void*)=%zu\n", sizeof(void *));
    print_cap("PCC", cheri_pcc_get());
    print_cap("DDC", cheri_ddc_get());

    uint8_t context_load_8[] = {
        INSN(0x79, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_load_b_8[] = {
        INSN(0x71, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_load_h_8[] = {
        INSN(0x69, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_load_w_8[] = {
        INSN(0x61, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_load_bsx_8[] = {
        INSN(0x91, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_load_hsx_8[] = {
        INSN(0x89, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_load_wsx_8[] = {
        INSN(0x81, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_load_4096[] = {
        INSN(0x79, 0, 1, 4096, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_alias_load_8[] = {
        INSN(0xbf, 6, 1, 0, 0),
        INSN(0x79, 0, 6, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_alias_load_4096[] = {
        INSN(0xbf, 6, 1, 0, 0),
        INSN(0x79, 0, 6, 4096, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_ptr_add_load_8[] = {
        INSN(0xbf, 6, 1, 0, 0),
        INSN(0x07, 6, 0, 0, 8),
        INSN(0x79, 0, 6, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_ptr_add_load_4096[] = {
        INSN(0xbf, 6, 1, 0, 0),
        INSN(0x07, 6, 0, 0, 4096),
        INSN(0x79, 0, 6, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t branch_preserves_context[] = {
        INSN(0xbf, 6, 1, 0, 0),
        INSN(0xb7, 0, 0, 0, 0),
        INSN(0x15, 0, 0, 1, 0),
        INSN(0xb7, 0, 0, 0, 1),
        INSN(0x79, 0, 6, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t branch_join_clobbered_context[] = {
        INSN(0xbf, 6, 1, 0, 0),
        INSN(0xb7, 0, 0, 0, 0),
        INSN(0x15, 0, 0, 2, 0),
        INSN(0xb7, 6, 0, 0, 0),
        INSN(0x05, 0, 0, 0, 0),
        INSN(0x79, 0, 6, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_store_load[] = {
        INSN(0xb7, 0, 0, 0, 42),
        INSN(0x7b, 0xa, 0, -8, 0),
        INSN(0xb7, 0, 0, 0, 0),
        INSN(0x79, 0, 0xa, -8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_store_load_b[] = {
        INSN(0xb7, 0, 0, 0, 0x12345678),
        INSN(0x73, 0xa, 0, -1, 0),
        INSN(0xb7, 0, 0, 0, 0),
        INSN(0x71, 0, 0xa, -1, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_store_load_h[] = {
        INSN(0xb7, 0, 0, 0, 0x12345678),
        INSN(0x6b, 0xa, 0, -2, 0),
        INSN(0xb7, 0, 0, 0, 0),
        INSN(0x69, 0, 0xa, -2, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_store_load_w[] = {
        INSN(0xb7, 0, 0, 0, 0x12345678),
        INSN(0x63, 0xa, 0, -4, 0),
        INSN(0xb7, 0, 0, 0, 0),
        INSN(0x61, 0, 0xa, -4, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_signed_load_b[] = {
        INSN(0x72, 0xa, 0, -1, -1),
        INSN(0x91, 0, 0xa, -1, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_signed_load_h[] = {
        INSN(0x6a, 0xa, 0, -2, -1),
        INSN(0x89, 0, 0xa, -2, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_signed_load_w[] = {
        INSN(0x62, 0xa, 0, -4, -1),
        INSN(0x81, 0, 0xa, -4, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t immediate_stack_store_load[] = {
        INSN(0x7a, 0xa, 0, -8, 42),
        INSN(0x79, 0, 0xa, -8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_ptr_add_store_load[] = {
        INSN(0xbf, 2, 10, 0, 0),
        INSN(0x07, 2, 0, 0, -16),
        INSN(0xb7, 0, 0, 0, 42),
        INSN(0x7b, 2, 0, 8, 0),
        INSN(0x79, 0, 2, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t uninit_stack_ptr_add_load[] = {
        INSN(0xbf, 2, 10, 0, 0),
        INSN(0x07, 2, 0, 0, -8),
        INSN(0x79, 0, 2, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_ptr_add_load_oob[] = {
        INSN(0xbf, 2, 10, 0, 0),
        INSN(0x07, 2, 0, 0, -4104),
        INSN(0x79, 0, 2, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_store_oob[] = {
        INSN(0xb7, 0, 0, 0, 42),
        INSN(0x7b, 0xa, 0, -4104, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t stack_load_oob[] = {
        INSN(0x79, 0, 0xa, -4104, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t context_store[] = {
        INSN(0xb7, 0, 0, 0, 42),
        INSN(0x7b, 1, 0, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t capability_stack_store[] = {
        INSN(0xbf, 2, 1, 0, 0),
        INSN(0x7b, 0xa, 2, -8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t clobbered_r1_load[] = {
        INSN(0xb7, 1, 0, 0, 0),
        INSN(0x79, 0, 1, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    int failures = 0;
    failures += run_compile_and_call("context_load_8", context_load_8, sizeof(context_load_8), 0xfeedfacecafebeefULL, 0);
    failures += run_compile_and_call("context_load_b_8", context_load_b_8, sizeof(context_load_b_8), 0xefULL, 0);
    failures += run_compile_and_call("context_load_h_8", context_load_h_8, sizeof(context_load_h_8), 0xbeefULL, 0);
    failures += run_compile_and_call("context_load_w_8", context_load_w_8, sizeof(context_load_w_8), 0xcafebeefULL, 0);
    failures += run_compile_and_call("context_load_bsx_8", context_load_bsx_8, sizeof(context_load_bsx_8), 0xffffffffffffffefULL, 0);
    failures += run_compile_and_call("context_load_hsx_8", context_load_hsx_8, sizeof(context_load_hsx_8), 0xffffffffffffbeefULL, 0);
    failures += run_compile_and_call("context_load_wsx_8", context_load_wsx_8, sizeof(context_load_wsx_8), 0xffffffffcafebeefULL, 0);
    failures += run_compile_and_call("context_load_4096", context_load_4096, sizeof(context_load_4096), 0, 1);
    failures += run_compile_and_call("context_alias_load_8", context_alias_load_8, sizeof(context_alias_load_8), 0xfeedfacecafebeefULL, 0);
    failures += run_compile_and_call("context_alias_load_4096", context_alias_load_4096, sizeof(context_alias_load_4096), 0, 1);
    failures += run_compile_and_call("context_ptr_add_load_8", context_ptr_add_load_8, sizeof(context_ptr_add_load_8), 0xfeedfacecafebeefULL, 0);
    failures += run_compile_and_call("context_ptr_add_load_4096", context_ptr_add_load_4096, sizeof(context_ptr_add_load_4096), 0, 1);
    failures += run_compile_and_call("branch_preserves_context", branch_preserves_context, sizeof(branch_preserves_context), 0xfeedfacecafebeefULL, 0);
    failures += run_compile_and_call("stack_store_load", stack_store_load, sizeof(stack_store_load), 42, 0);
    failures += run_compile_and_call("stack_store_load_b", stack_store_load_b, sizeof(stack_store_load_b), 0x78ULL, 0);
    failures += run_compile_and_call("stack_store_load_h", stack_store_load_h, sizeof(stack_store_load_h), 0x5678ULL, 0);
    failures += run_compile_and_call("stack_store_load_w", stack_store_load_w, sizeof(stack_store_load_w), 0x12345678ULL, 0);
    failures += run_compile_and_call("stack_signed_load_b", stack_signed_load_b, sizeof(stack_signed_load_b), 0xffffffffffffffffULL, 0);
    failures += run_compile_and_call("stack_signed_load_h", stack_signed_load_h, sizeof(stack_signed_load_h), 0xffffffffffffffffULL, 0);
    failures += run_compile_and_call("stack_signed_load_w", stack_signed_load_w, sizeof(stack_signed_load_w), 0xffffffffffffffffULL, 0);
    failures += run_compile_and_call("immediate_stack_store_load", immediate_stack_store_load, sizeof(immediate_stack_store_load), 42, 0);
    failures += run_compile_and_call("stack_ptr_add_store_load", stack_ptr_add_store_load, sizeof(stack_ptr_add_store_load), 42, 0);
    failures += run_compile_and_call("uninit_stack_ptr_add_load", uninit_stack_ptr_add_load, sizeof(uninit_stack_ptr_add_load), 0, 0);
    failures += run_compile_and_call("stack_store_oob", stack_store_oob, sizeof(stack_store_oob), 0, 1);
    failures += run_compile_and_call("stack_load_oob", stack_load_oob, sizeof(stack_load_oob), 0, 1);
    failures += run_compile_and_call("stack_ptr_add_load_oob", stack_ptr_add_load_oob, sizeof(stack_ptr_add_load_oob), 0, 1);
    failures += expect_compile_reject("context_store", context_store, sizeof(context_store));
    failures += expect_compile_reject("capability_stack_store", capability_stack_store, sizeof(capability_stack_store));
    failures += expect_compile_reject("clobbered_r1_load", clobbered_r1_load, sizeof(clobbered_r1_load));
    failures += expect_compile_reject("branch_join_clobbered_context", branch_join_clobbered_context, sizeof(branch_join_clobbered_context));

    if (failures == 0) {
        printf("\nOK integrated CHERI direct-JIT compile path passed\n");
        return 0;
    }
    printf("\nFAIL integrated CHERI direct-JIT compile failures=%d\n", failures);
    return 1;
}
