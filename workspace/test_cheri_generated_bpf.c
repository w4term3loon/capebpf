#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ubpf.h"

#define GENERATED_BPF_OBJECT "/mnt/bpf/stack_array.o"
#define GENERATED_BPF_SYMBOL "foo"
#define EXPECTED_RESULT 0x6aULL

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

int
main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("generated BPF CHERI JIT test\n");
    printf("  object:   %s\n", GENERATED_BPF_OBJECT);
    printf("  symbol:   %s\n", GENERATED_BPF_SYMBOL);

    size_t elf_len = 0;
    void* elf = read_file(GENERATED_BPF_OBJECT, &elf_len);
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
    if (ubpf_load_elf_ex(vm, elf, elf_len, GENERATED_BPF_SYMBOL, &errmsg) < 0) {
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
    printf("  expected: 0x%" PRIx64 "\n", (uint64_t)EXPECTED_RESULT);

    ubpf_destroy(vm);
    free(elf);
    return result == EXPECTED_RESULT ? 0 : 1;
}
