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

    if (ctx->a == 0x1000) {
        return words[512];
    }

    return ctx->b;
}
