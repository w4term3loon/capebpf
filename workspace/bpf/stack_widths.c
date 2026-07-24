typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;

struct ctx {
    u64 a;
    u64 b;
};

__attribute__((noinline))
int
foo(struct ctx* ctx)
{
    volatile u64 wide[1];
    volatile u32 word[1];
    volatile u16 half[1];

    wide[0] = ctx->a;
    word[0] = (u32)ctx->b;
    half[0] = 0x1234;

    return (int)(wide[0] >> 8) + (int)(word[0] >> 8) + (int)(half[0] & 0xff);
}
