#include <stdint.h>

__attribute__((visibility("default")))
uint64_t
loader_jit_load_u64(uint64_t *p)
{
    return *(volatile uint64_t *)(p + 1);
}

__attribute__((visibility("default")))
uint64_t
loader_jit_load_u64_oob(uint64_t *p)
{
    return *(volatile uint64_t *)((char *)p + 4096);
}
