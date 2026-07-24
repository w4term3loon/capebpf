typedef unsigned long long u64;

extern void* map_lookup_value(void* ctx);

__attribute__((noinline))
u64
foo(void* ctx)
{
    volatile u64* map = (volatile u64*)map_lookup_value(ctx);
    return map[512];
}
