
#include <cheriintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define INSN(op, dst, src, off, imm) \
    (uint8_t)(op), (uint8_t)((dst) | ((src) << 4)), \
    (uint8_t)((off) & 0xff), (uint8_t)(((off) >> 8) & 0xff), \
    (uint8_t)((imm) & 0xff), (uint8_t)(((imm) >> 8) & 0xff), \
    (uint8_t)(((imm) >> 16) & 0xff), (uint8_t)(((imm) >> 24) & 0xff)

typedef uint64_t (*ctx_load_helper_fn)(void *mem, size_t len, int64_t offset);
typedef uint64_t (*tail_jit_fn)(ctx_load_helper_fn helper, void *mem, size_t len);

static uint64_t
ctx_load_u64_helper(void *mem, size_t len, int64_t offset)
{
    /* The len argument documents the intended ABI. This proof deliberately
     * relies on CHERI bounds rather than a software bounds check. */
    (void)len;
    return *(uint64_t *)((char *)mem + offset);
}

static int16_t
read_i16(const uint8_t *p)
{
    return (int16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint8_t
insn_dst(const uint8_t *insn)
{
    return insn[1] & 0x0f;
}

static uint8_t
insn_src(const uint8_t *insn)
{
    return insn[1] >> 4;
}

static void
emit_u32(uint8_t *buf, size_t *offset, uint32_t insn)
{
    memcpy(buf + *offset, &insn, sizeof(insn));
    *offset += sizeof(insn);
}

static int
compile_final_context_load_tail_helper(const uint8_t *prog, size_t prog_len, tail_jit_fn *out)
{
    if (prog_len != 16 || prog[0] != 0x79 || insn_dst(prog) != 0 || insn_src(prog) != 1 || prog[8] != 0x95) {
        fprintf(stderr, "unsupported program shape for tail-helper context-load proof\n");
        return 1;
    }

    int16_t offset = read_i16(&prog[2]);
    if (offset < 0) {
        fprintf(stderr, "negative offsets are not implemented in this proof\n");
        return 1;
    }

    uint8_t *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC | PROT_CAP,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    size_t pc = 0;
    emit_u32(code, &pc, 0xc2c1d003U); /* mov c3, c0: helper capability */
    emit_u32(code, &pc, 0xc2c1d020U); /* mov c0, c1: mem capability */
    emit_u32(code, &pc, 0xaa0203e1U); /* mov x1, x2: len */
    emit_u32(code, &pc, 0xd2800002U | ((uint32_t)offset << 5)); /* movz x2, #offset */
    emit_u32(code, &pc, 0xc2c21060U); /* br c3: tail-call helper */

    *out = (tail_jit_fn)cheri_sentry_create(code);
    return 0;
}

static int
run_child_expect_value(const char *name, tail_jit_fn fn, uint64_t expected)
{
    uint64_t mem[] = {0x1111111111111111ULL, 0xfeedfacecafebeefULL};
    pid_t pid = fork();
    if (pid == 0) {
        uint64_t result = fn(ctx_load_u64_helper, mem, sizeof(mem));
        printf("OK?  %s returned 0x%llx\n", name, (unsigned long long)result);
        _exit(result == expected ? 0 : 2);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("FAIL %s: trapped with signal %d\n", name, WTERMSIG(status));
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("FAIL %s: child exit=%d\n", name, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }
    printf("OK   %s: in-bounds helper load matched\n", name);
    return 0;
}

static int
run_child_expect_trap(const char *name, tail_jit_fn fn)
{
    uint64_t mem[] = {0x1111111111111111ULL, 0x2222222222222222ULL};
    pid_t pid = fork();
    if (pid == 0) {
        uint64_t result = fn(ctx_load_u64_helper, mem, sizeof(mem));
        printf("FAIL %s returned 0x%llx\n", name, (unsigned long long)result);
        _exit(2);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("OK   %s: helper load trapped with signal %d\n", name, WTERMSIG(status));
        return 0;
    }
    printf("FAIL %s: child exit=%d\n", name, WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 1;
}

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    uint8_t in_bounds_prog[] = {
        INSN(0x79, 0, 1, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t oob_prog[] = {
        INSN(0x79, 0, 1, 4096, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    tail_jit_fn in_bounds = NULL;
    tail_jit_fn oob = NULL;
    if (compile_final_context_load_tail_helper(in_bounds_prog, sizeof(in_bounds_prog), &in_bounds) != 0 ||
        compile_final_context_load_tail_helper(oob_prog, sizeof(oob_prog), &oob) != 0) {
        return 1;
    }

    int failures = 0;
    failures += run_child_expect_value("tail_helper_context_in_bounds", in_bounds, 0xfeedfacecafebeefULL);
    failures += run_child_expect_trap("tail_helper_context_oob", oob);
    return failures == 0 ? 0 : 1;
}
