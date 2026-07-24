typedef unsigned long long u64;

struct ctx {
    u64 a;
    u64 b;
};

__attribute__((noinline))
int
foo(struct ctx* ctx)
{
    volatile unsigned char slots[40];
    unsigned int index = (unsigned int)ctx->a;

    slots[index] = 0x5a;
    return slots[index];
}
