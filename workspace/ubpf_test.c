#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ubpf.h"

int main(void)
{
    /* eBPF: r0 = 42; exit */
    uint8_t prog[] = {
        0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    /* ────────── interpreter ────────── */
    struct ubpf_vm *vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "ubpf_create failed\n");
        return 1;
    }

    char *errmsg = NULL;
    if (ubpf_load(vm, prog, sizeof(prog), &errmsg) != 0) {
        fprintf(stderr, "ubpf_load: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    uint64_t result;
    if (ubpf_exec(vm, NULL, 0, &result) != 0) {
        fprintf(stderr, "ubpf_exec (interp) failed\n");
        ubpf_destroy(vm);
        return 1;
    }
    printf("interpreter: r0 = %llu  (expected 42)\n", (unsigned long long)result);

    /* ────────── JIT ────────── */
    errmsg = NULL;
    ubpf_jit_fn jit = ubpf_compile(vm, &errmsg);
    if (!jit) {
        fprintf(stderr, "ubpf_compile (JIT): %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 2;
    }

    result = jit(NULL, 0);
    printf("       JIT: r0 = %llu  (expected 42)\n", (unsigned long long)result);

    ubpf_destroy(vm);
    return 0;
}
