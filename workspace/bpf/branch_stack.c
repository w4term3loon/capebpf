typedef unsigned long long u64;

struct ctx {
    u64 a;
    u64 b;
};

__attribute__((noinline))
int
foo(struct ctx* ctx)
{
    volatile unsigned char slot[8];

    if (ctx->a & 1) {
        slot[3] = 0x11;
    } else {
        slot[3] = 0x22;
    }

    return slot[3] + (int)(ctx->b >> 12);
}
