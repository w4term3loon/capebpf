#include <cheriintrin.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define IN_BOUNDS_LIB "/mnt/cheri_objjit_offset_8.so"
#define OOB_LIB "/mnt/cheri_objjit_offset_4096.so"
#define ENTRY_SYMBOL "bpf_entry"

typedef uint64_t (*bpf_entry_fn)(uint64_t *ctx);

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
    case PROT_CHERI_IMPRECISE:
        return "PROT_CHERI_IMPRECISE";
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
run_generated_object(const char *name, const char *lib_path, int expect_trap)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        install_sigprot_handler(expect_trap);
        printf("\n[object-backed CHERI JIT %s]\n", name);
        uint64_t ctx[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
        print_cap("ctx arg", ctx);

        void *handle = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            printf("  dlopen failed: %s\n", dlerror());
            _exit(10);
        }
        dlerror();
        bpf_entry_fn fn = (bpf_entry_fn)dlsym(handle, ENTRY_SYMBOL);
        const char *err = dlerror();
        if (err) {
            printf("  dlsym failed: %s\n", err);
            _exit(11);
        }
        print_cap("generated entry", (const void *)fn);
        uint64_t result = fn(ctx);
        printf("  returned              0x%llx\n", (unsigned long long)result);
        if (expect_trap) {
            _exit(20);
        }
        _exit(result == ctx[1] ? 0 : 21);
    }
    return wait_for_child(pid, expect_trap);
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("object-backed CHERI JIT context-load repro: sizeof(void*)=%zu\n", sizeof(void *));
    print_cap("PCC", cheri_pcc_get());
    print_cap("DDC", cheri_ddc_get());

    int failures = 0;
    failures += run_generated_object("context_load_8", IN_BOUNDS_LIB, 0);
    failures += run_generated_object("context_load_4096", OOB_LIB, 1);
    if (failures == 0) {
        printf("\nOK object-backed CHERI JIT context load produced an in-bounds/OOB differential\n");
        return 0;
    }
    printf("\nFAIL object-backed CHERI JIT context-load failures=%d\n", failures);
    return 1;
}
