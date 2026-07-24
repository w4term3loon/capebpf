typedef unsigned long long u64;

struct ctx {
    u64 a;
    u64 b;
};

__attribute__((noinline))
u64
foo(struct ctx* ctx)
{
    volatile u64* words = (volatile u64*)ctx;
    u64 index = (ctx->a >> 12) & 1;

    return words[index];
}
