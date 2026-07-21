#include <cheriintrin.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/procctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ucontext.h>

/* Compiler-verified Morello purecap bytes:
 *   mov w0, #42           -> 52800540
 *   gctag x8, c0          -> c2c09008
 *   cmp x8, #0            -> f100011f
 *   cset w0, ne           -> 1a9f07e0
 *   gclen x0, c0          -> c2c03000
 *   ldr x0, [c0, #offset] -> f9400000 | ((offset / 8) << 10)
 *   ret c30               -> c2c253c0
 */

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
    case PROT_CHERI_STORELOCAL:
        return "PROT_CHERI_STORELOCAL";
    case PROT_CHERI_CINVOKE:
        return "PROT_CHERI_CINVOKE";
    case PROT_CHERI_SYSREG:
        return "PROT_CHERI_SYSREG";
    case PROT_CHERI_UNALIGNED_BASE:
        return "PROT_CHERI_UNALIGNED_BASE";
    default:
        return "UNKNOWN";
    }
}

static void
sig_dump_cap(FILE *out, const char *label, const void *cap)
{
    fprintf(out,
        "  trap %-16s tag=%d sealed=%d sentry=%d addr=0x%zx base=0x%zx len=0x%zx perms=0x%zx flags=0x%zx\n",
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

static void
sig_dump_ucontext(FILE *out, void *uctx)
{
    ucontext_t *uc = (ucontext_t *)uctx;
    if (!uc) {
        fprintf(out, "  trap ucontext         <null>\n");
        return;
    }

    fprintf(out, "  trap mc_flags         0x%x\n", uc->uc_mcontext.mc_flags);
    fprintf(out, "  trap mc_spsr          0x%x\n", uc->uc_mcontext.mc_spsr);
    sig_dump_cap(out, "cap_elr", (const void *)uc->uc_mcontext.mc_capregs.cap_elr);
    sig_dump_cap(out, "c0", (const void *)uc->uc_mcontext.mc_capregs.cap_x[0]);
    sig_dump_cap(out, "c1", (const void *)uc->uc_mcontext.mc_capregs.cap_x[1]);
    sig_dump_cap(out, "c30/lr", (const void *)uc->uc_mcontext.mc_capregs.cap_lr);
    sig_dump_cap(out, "csp", (const void *)uc->uc_mcontext.mc_capregs.cap_sp);
    sig_dump_cap(out, "ddc", (const void *)uc->uc_mcontext.mc_capregs.cap_ddc);
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
    sig_dump_ucontext(stderr, uctx);
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

typedef uint64_t (*const_fn)(void);
typedef uint64_t (*tag_fn)(uint64_t *mem);
typedef uint64_t (*direct_load_fn)(uint64_t *mem);
typedef uint64_t (*scalar_load_fn)(uint64_t addr);

typedef struct repro_variant {
    const char *name;
    int mmap_prot;
    int mprotect_prot;
    int use_mprotect;
    int make_sentry_before_mprotect;
    int use_sentry;
    int use_capmode_entry;
} repro_variant_t;

typedef enum repro_program {
    PROGRAM_CONST42,
    PROGRAM_TAG_C0,
    PROGRAM_LEN_C0,
    PROGRAM_LOAD_C0_OFFSET,
} repro_program_t;

__attribute__((noinline))
static uint64_t
elf_c_load_ref(uint64_t *p)
{
    return *(volatile uint64_t *)(p + 1);
}

static void
emit_u32(uint8_t *buf, size_t *offset, uint32_t insn)
{
    memcpy(buf + *offset, &insn, sizeof(insn));
    *offset += sizeof(insn);
}

static uint32_t
encode_ldr_x0_c0_offset(uint32_t byte_offset)
{
    if (byte_offset % 8 != 0 || byte_offset / 8 >= 0x1000) {
        fprintf(stderr, "unsupported offset %u for ldr x0, [c0, #imm]\n", byte_offset);
        _exit(100);
    }
    return 0xf9400000U | ((byte_offset / 8) << 10);
}

static void
emit_program(uint8_t *code, size_t *pc, repro_program_t program, uint32_t byte_offset)
{
    switch (program) {
    case PROGRAM_CONST42:
        emit_u32(code, pc, 0x52800540U); /* mov w0, #42 */
        break;
    case PROGRAM_TAG_C0:
        emit_u32(code, pc, 0xc2c09008U); /* gctag x8, c0 */
        emit_u32(code, pc, 0xf100011fU); /* cmp x8, #0 */
        emit_u32(code, pc, 0x1a9f07e0U); /* cset w0, ne */
        break;
    case PROGRAM_LEN_C0:
        emit_u32(code, pc, 0xc2c03000U); /* gclen x0, c0 */
        break;
    case PROGRAM_LOAD_C0_OFFSET:
        emit_u32(code, pc, encode_ldr_x0_c0_offset(byte_offset));
        break;
    }
    emit_u32(code, pc, 0xc2c253c0U); /* ret c30 */
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

static void *
make_entry_cap(uint8_t *code, const repro_variant_t *variant)
{
    void *entry = code;
    if (variant->use_capmode_entry) {
        entry = (void *)((uintptr_t)entry | 1U);
        print_cap("entry capmode", entry);
    }
    if (variant->use_sentry) {
        entry = cheri_sentry_create(entry);
    }
    return entry;
}

static void *
compile_generated_program(repro_program_t program, uint32_t byte_offset, const repro_variant_t *variant)
{
    const size_t page_size = 4096;
    int max_prot = PROT_READ | PROT_WRITE | PROT_EXEC;
#ifdef PROT_CAP
    if (variant->mmap_prot & PROT_CAP || variant->mprotect_prot & PROT_CAP) {
        max_prot |= PROT_CAP;
    }
#endif

    uint8_t *code = mmap(NULL, page_size,
        variant->mmap_prot | PROT_MAX(max_prot),
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        printf("  mmap failed: %s\n", strerror(errno));
        return NULL;
    }

    size_t pc = 0;
    emit_program(code, &pc, program, byte_offset);
    __builtin___clear_cache((char *)code, (char *)code + pc);

    printf("  emitted bytes         ");
    for (size_t i = 0; i < pc; i++) {
        printf(" %02x", code[i]);
    }
    printf("\n");
    print_cap("code after mmap", code);

    void *entry = NULL;
    if (variant->make_sentry_before_mprotect) {
        entry = make_entry_cap(code, variant);
        print_cap("entry before mprot", entry);
    }

    if (variant->use_mprotect) {
        if (mprotect(code, page_size, variant->mprotect_prot) != 0) {
            printf("  mprotect failed: %s\n", strerror(errno));
            munmap(code, page_size);
            return NULL;
        }
        print_cap("code after mprot", code);
    }

    if (!entry) {
        entry = make_entry_cap(code, variant);
        print_cap(variant->use_sentry ? "entry after mprot" : "entry raw code", entry);
    }

    return entry;
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
        int sig = WTERMSIG(status);
        printf("  parent: child trapped with signal %d\n", sig);
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
run_const42_child(const repro_variant_t *variant)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        install_sigprot_handler(0);
        printf("\n[%s const42]\n", variant->name);
        const_fn fn = (const_fn)compile_generated_program(PROGRAM_CONST42, 0, variant);
        if (!fn) {
            _exit(10);
        }
        uint64_t result = fn();
        printf("  returned              0x%llx\n", (unsigned long long)result);
        _exit(result == 42 ? 0 : 21);
    }
    return wait_for_child(pid, 0);
}

static int
run_tag_child(const repro_variant_t *variant)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        uint64_t mem[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
        install_sigprot_handler(0);
        printf("\n[%s tag_c0]\n", variant->name);
        print_cap("mem arg", mem);
        tag_fn fn = (tag_fn)compile_generated_program(PROGRAM_TAG_C0, 0, variant);
        if (!fn) {
            _exit(10);
        }
        uint64_t result = fn(mem);
        printf("  returned              0x%llx\n", (unsigned long long)result);
        _exit(result == 1 ? 0 : 21);
    }
    return wait_for_child(pid, 0);
}

static int
run_len_child(const repro_variant_t *variant)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        uint64_t mem[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
        install_sigprot_handler(0);
        printf("\n[%s len_c0]\n", variant->name);
        print_cap("mem arg", mem);
        tag_fn fn = (tag_fn)compile_generated_program(PROGRAM_LEN_C0, 0, variant);
        if (!fn) {
            _exit(10);
        }
        uint64_t result = fn(mem);
        printf("  returned              0x%llx\n", (unsigned long long)result);
        _exit(result == sizeof(mem) ? 0 : 21);
    }
    return wait_for_child(pid, 0);
}

static int
run_load_child(const repro_variant_t *variant, uint32_t offset, int expect_trap)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        uint64_t mem[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
        install_sigprot_handler(expect_trap);
        printf("\n[%s load offset=%u]\n", variant->name, offset);
        print_cap("mem arg", mem);
        direct_load_fn fn = (direct_load_fn)compile_generated_program(PROGRAM_LOAD_C0_OFFSET, offset, variant);
        if (!fn) {
            _exit(10);
        }
        uint64_t result = fn(mem);
        printf("  returned              0x%llx\n", (unsigned long long)result);
        if (expect_trap) {
            _exit(20);
        }
        _exit(result == mem[1] ? 0 : 21);
    }
    return wait_for_child(pid, expect_trap);
}

static int
run_scalar_address_load_child(const repro_variant_t *variant)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        uint64_t mem[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
        install_sigprot_handler(1);
        printf("\n[%s scalar-address load offset=8]\n", variant->name);
        print_cap("mem arg", mem);
        scalar_load_fn fn = (scalar_load_fn)compile_generated_program(PROGRAM_LOAD_C0_OFFSET, 8, variant);
        if (!fn) {
            _exit(10);
        }
        uint64_t addr = (uint64_t)cheri_address_get(mem);
        printf("  scalar addr           0x%llx\n", (unsigned long long)addr);
        uint64_t result = fn(addr);
        printf("  returned              0x%llx\n", (unsigned long long)result);
        _exit(20);
    }
    return wait_for_child(pid, 1);
}

static int
run_elf_text_load_child(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        uint64_t mem[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
        install_sigprot_handler(0);
        printf("\n[elf .text load controls]\n");
        print_cap("mem arg", mem);
        print_cap("elf c load fn", (const void *)elf_c_load_ref);

        uint64_t c_result = elf_c_load_ref(mem);
        printf("  elf c load returned   0x%llx\n", (unsigned long long)c_result);
        _exit(c_result == mem[1] ? 0 : 21);
    }
    return wait_for_child(pid, 0);
}

static void
print_procctl_status(void)
{
    int status = 0;
    if (procctl(P_PID, 0, PROC_PROTMAX_STATUS, &status) == 0) {
        printf("  PROC_PROTMAX_STATUS  0x%x\n", status);
    } else {
        printf("  PROC_PROTMAX_STATUS  failed: %s\n", strerror(errno));
    }

    status = 0;
    if (procctl(P_PID, 0, PROC_WXMAP_STATUS, &status) == 0) {
        printf("  PROC_WXMAP_STATUS    0x%x\n", status);
    } else {
        printf("  PROC_WXMAP_STATUS    failed: %s\n", strerror(errno));
    }
}

static int
run_procctl_load_child(const char *name, const repro_variant_t *variant, int protmax_ctl, int wxmap_ctl)
{
    pid_t pid = fork();
    if (pid == 0) {
        setvbuf(stdout, NULL, _IONBF, 0);
        uint64_t mem[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
        install_sigprot_handler(0);
        printf("\n[%s load offset=8]\n", name);
        print_procctl_status();

        int ctl = protmax_ctl;
        if (procctl(P_PID, 0, PROC_PROTMAX_CTL, &ctl) != 0) {
            printf("  PROC_PROTMAX_CTL     failed: %s\n", strerror(errno));
        }
        ctl = wxmap_ctl;
        if (procctl(P_PID, 0, PROC_WXMAP_CTL, &ctl) != 0) {
            printf("  PROC_WXMAP_CTL       failed: %s\n", strerror(errno));
        }
        print_procctl_status();

        print_cap("mem arg", mem);
        direct_load_fn fn = (direct_load_fn)compile_generated_program(PROGRAM_LOAD_C0_OFFSET, 8, variant);
        if (!fn) {
            _exit(10);
        }
        uint64_t result = fn(mem);
        printf("  returned              0x%llx\n", (unsigned long long)result);
        _exit(result == mem[1] ? 0 : 21);
    }
    return wait_for_child(pid, 0);
}


int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("direct CHERI JIT repro: sizeof(void*)=%zu\n", sizeof(void *));
    print_cap("PCC", cheri_pcc_get());
    print_cap("DDC", cheri_ddc_get());

    const repro_variant_t variants[] = {
        {
            .name = "rwx_current_no_mprotect",
            .mmap_prot = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_CAP,
            .mprotect_prot = 0,
            .use_mprotect = 0,
            .make_sentry_before_mprotect = 0,
            .use_sentry = 1,
            .use_capmode_entry = 1,
        },
        {
            .name = "rwx_current_then_rx_sentry_after",
            .mmap_prot = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_CAP,
            .mprotect_prot = PROT_READ | PROT_EXEC | PROT_CAP,
            .use_mprotect = 1,
            .make_sentry_before_mprotect = 0,
            .use_sentry = 1,
            .use_capmode_entry = 1,
        },
        {
            .name = "rwx_current_then_rx_sentry_before",
            .mmap_prot = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_CAP,
            .mprotect_prot = PROT_READ | PROT_EXEC | PROT_CAP,
            .use_mprotect = 1,
            .make_sentry_before_mprotect = 1,
            .use_sentry = 1,
            .use_capmode_entry = 1,
        },
        {
            .name = "rw_current_max_rwx_then_rx",
            .mmap_prot = PROT_READ | PROT_WRITE | PROT_CAP,
            .mprotect_prot = PROT_READ | PROT_EXEC | PROT_CAP,
            .use_mprotect = 1,
            .make_sentry_before_mprotect = 0,
            .use_sentry = 1,
            .use_capmode_entry = 1,
        },
        {
            .name = "rwx_current_no_prot_cap",
            .mmap_prot = PROT_READ | PROT_WRITE | PROT_EXEC,
            .mprotect_prot = 0,
            .use_mprotect = 0,
            .make_sentry_before_mprotect = 0,
            .use_sentry = 1,
            .use_capmode_entry = 1,
        },
        {
            .name = "rwx_current_raw_entry_no_mprotect",
            .mmap_prot = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_CAP,
            .mprotect_prot = 0,
            .use_mprotect = 0,
            .make_sentry_before_mprotect = 0,
            .use_sentry = 0,
            .use_capmode_entry = 1,
        },
    };

    int failures = 0;
    failures += run_elf_text_load_child();
    failures += run_procctl_load_child(
        "procctl_force_protmax_wx_permit", &variants[1], PROC_PROTMAX_FORCE_ENABLE, PROC_WX_MAPPINGS_PERMIT);
    failures += run_procctl_load_child(
        "procctl_force_no_protmax_wx_disallow_exec",
        &variants[1],
        PROC_PROTMAX_FORCE_DISABLE,
        PROC_WX_MAPPINGS_DISALLOW_EXEC);
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        failures += run_const42_child(&variants[i]);
        failures += run_tag_child(&variants[i]);
        failures += run_len_child(&variants[i]);
        failures += run_load_child(&variants[i], 8, 0);
        failures += run_load_child(&variants[i], 4096, 1);
        failures += run_scalar_address_load_child(&variants[i]);
    }

    if (failures == 0) {
        printf("\nOK direct CHERI JIT repro passed all variants\n");
        return 0;
    }

    printf("\nFAIL direct CHERI JIT repro failures=%d\n", failures);
    return 1;
}
