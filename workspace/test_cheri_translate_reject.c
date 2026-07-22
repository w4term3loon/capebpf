#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ubpf.h"
#include "ubpf_int.h"

#define INSN(op, dst, src, off, imm) \
    (uint8_t)(op), (uint8_t)((dst) | ((src) << 4)), \
    (uint8_t)((off) & 0xff), (uint8_t)(((off) >> 8) & 0xff), \
    (uint8_t)((imm) & 0xff), (uint8_t)(((imm) >> 8) & 0xff), \
    (uint8_t)(((imm) >> 16) & 0xff), (uint8_t)(((imm) >> 24) & 0xff)

static int
translate_with_cheri_backend(const uint8_t *prog, size_t prog_len, char **errmsg)
{
    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "ubpf_create failed\n");
        return -1;
    }

    vm->jit_translate = ubpf_translate_arm64_cheri;

    if (ubpf_load(vm, prog, (uint32_t)prog_len, errmsg) != 0) {
        ubpf_destroy(vm);
        return -1;
    }

    uint8_t buffer[65536] = {0};
    size_t size = sizeof(buffer);
    int rc = ubpf_translate_ex(vm, buffer, &size, errmsg, BasicJitMode);
    ubpf_destroy(vm);
    return rc;
}

static int
expect_translate_ok(const char *name, const uint8_t *prog, size_t prog_len)
{
    char *errmsg = NULL;
    int rc = translate_with_cheri_backend(prog, prog_len, &errmsg);
    if (rc != 0) {
        printf("FAIL %s: unexpected CHERI translate reject: %s\n",
            name, errmsg ? errmsg : "<no error>");
        free(errmsg);
        return 1;
    }
    printf("OK   %s: CHERI translate accepted\n", name);
    return 0;
}

static int
expect_translate_reject(const char *name, const uint8_t *prog, size_t prog_len)
{
    char *errmsg = NULL;
    int rc = translate_with_cheri_backend(prog, prog_len, &errmsg);
    if (rc == 0) {
        printf("FAIL %s: CHERI translate unexpectedly accepted unsupported memory operation\n", name);
        return 1;
    }

    int matched = errmsg &&
        (strstr(errmsg, "does not yet support memory opcode") ||
         strstr(errmsg, "tracked context or stack capabilities") ||
         strstr(errmsg, "tracked stack capabilities") ||
         strstr(errmsg, "does not allow storing a capability value") ||
         strstr(errmsg, "does not allow returning a capability value"));
    printf("%s %s: CHERI translate rejected: %s\n",
        matched ? "OK  " : "FAIL", name, errmsg ? errmsg : "<no error>");
    free(errmsg);
    return matched ? 0 : 1;
}

int
main(void)
{
    uint8_t scalar[] = {
        INSN(0xb7, 0, 0, 0, 42),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t stack_store_load[] = {
        INSN(0xb7, 0, 0, 0, 42),
        INSN(0x7b, 0xa, 0, -8, 0),
        INSN(0xb7, 0, 0, 0, 0),
        INSN(0x79, 0, 0xa, -8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t immediate_stack_store[] = {
        INSN(0x7a, 0xa, 0, -8, 42),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t context_load[] = {
        INSN(0x79, 0, 1, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t context_width_loads[] = {
        INSN(0x71, 0, 1, 8, 0),
        INSN(0x69, 0, 1, 8, 0),
        INSN(0x61, 0, 1, 8, 0),
        INSN(0x79, 0, 1, 8, 0),
        INSN(0x91, 0, 1, 8, 0),
        INSN(0x89, 0, 1, 8, 0),
        INSN(0x81, 0, 1, 8, 0),
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

    uint8_t context_oob_load[] = {
        INSN(0x79, 0, 1, 4096, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t context_ptr_add_load[] = {
        INSN(0xbf, 6, 1, 0, 0),
        INSN(0x07, 6, 0, 0, 8),
        INSN(0x79, 0, 6, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t context_ptr_add_oob_load[] = {
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

    uint8_t stack_ptr_add_store_load[] = {
        INSN(0xbf, 2, 10, 0, 0),
        INSN(0x07, 2, 0, 0, -16),
        INSN(0xb7, 0, 0, 0, 42),
        INSN(0x7b, 2, 0, 8, 0),
        INSN(0x79, 0, 2, 8, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t stack_width_store_loads[] = {
        INSN(0xb7, 0, 0, 0, 0x12345678),
        INSN(0x73, 0xa, 0, -1, 0),
        INSN(0x71, 0, 0xa, -1, 0),
        INSN(0x6b, 0xa, 0, -2, 0),
        INSN(0x69, 0, 0xa, -2, 0),
        INSN(0x63, 0xa, 0, -4, 0),
        INSN(0x61, 0, 0xa, -4, 0),
        INSN(0x7b, 0xa, 0, -16, 0),
        INSN(0x79, 0, 0xa, -16, 0),
        INSN(0x72, 0xa, 0, -17, -1),
        INSN(0x91, 0, 0xa, -17, 0),
        INSN(0x6a, 0xa, 0, -20, -1),
        INSN(0x89, 0, 0xa, -20, 0),
        INSN(0x62, 0xa, 0, -24, -1),
        INSN(0x81, 0, 0xa, -24, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t uninit_stack_ptr_add_load[] = {
        INSN(0xbf, 2, 10, 0, 0),
        INSN(0x07, 2, 0, 0, -8),
        INSN(0x79, 0, 2, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t clobbered_r1_load[] = {
        INSN(0xb7, 1, 0, 0, 0),
        INSN(0x79, 0, 1, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    uint8_t pointer_leak[] = {
        INSN(0xbf, 2, 10, 0, 0),
        INSN(0xbf, 0, 2, 0, 0),
        INSN(0x95, 0, 0, 0, 0),
    };

    int failures = 0;
    failures += expect_translate_ok("scalar_mov_exit", scalar, sizeof(scalar));
    failures += expect_translate_ok("context_load", context_load, sizeof(context_load));
    failures += expect_translate_ok("context_width_loads", context_width_loads, sizeof(context_width_loads));
    failures += expect_translate_ok("context_oob_load", context_oob_load, sizeof(context_oob_load));
    failures += expect_translate_ok("context_ptr_add_load", context_ptr_add_load, sizeof(context_ptr_add_load));
    failures += expect_translate_ok("context_ptr_add_oob_load", context_ptr_add_oob_load, sizeof(context_ptr_add_oob_load));
    failures += expect_translate_ok("branch_preserves_context", branch_preserves_context, sizeof(branch_preserves_context));
    failures += expect_translate_ok("stack_store_load", stack_store_load, sizeof(stack_store_load));
    failures += expect_translate_ok("stack_ptr_add_store_load", stack_ptr_add_store_load, sizeof(stack_ptr_add_store_load));
    failures += expect_translate_ok("stack_width_store_loads", stack_width_store_loads, sizeof(stack_width_store_loads));
    failures += expect_translate_ok("uninit_stack_ptr_add_load", uninit_stack_ptr_add_load, sizeof(uninit_stack_ptr_add_load));
    failures += expect_translate_ok("immediate_stack_store", immediate_stack_store, sizeof(immediate_stack_store));
    failures += expect_translate_reject("context_store", context_store, sizeof(context_store));
    failures += expect_translate_reject("capability_stack_store", capability_stack_store, sizeof(capability_stack_store));
    failures += expect_translate_reject("clobbered_r1_load", clobbered_r1_load, sizeof(clobbered_r1_load));
    failures += expect_translate_reject("branch_join_clobbered_context", branch_join_clobbered_context, sizeof(branch_join_clobbered_context));
    failures += expect_translate_reject("pointer_leak", pointer_leak, sizeof(pointer_leak));
    return failures == 0 ? 0 : 1;
}
