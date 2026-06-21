#ifndef CHERI_JIT_CONTRACT_H
#define CHERI_JIT_CONTRACT_H

#include <stdbool.h>
#include <stdint.h>

#define CHERI_BPF_REG_COUNT 11

enum cheri_bpf_value_kind {
    CHERI_BPF_VALUE_SCALAR = 0,
    CHERI_BPF_VALUE_CAPABILITY = 1,
};

enum cheri_bpf_cap_source {
    CHERI_BPF_CAP_NONE = 0,
    CHERI_BPF_CAP_CONTEXT,
    CHERI_BPF_CAP_STACK,
    CHERI_BPF_CAP_MAP_VALUE,
    CHERI_BPF_CAP_HELPER_RETURN,
};

struct cheri_bpf_reg_state {
    enum cheri_bpf_value_kind kind;
    enum cheri_bpf_cap_source source;
    uint32_t bounds_id;
};

static inline void
cheri_bpf_mark_scalar(struct cheri_bpf_reg_state *reg)
{
    reg->kind = CHERI_BPF_VALUE_SCALAR;
    reg->source = CHERI_BPF_CAP_NONE;
    reg->bounds_id = 0;
}

static inline void
cheri_bpf_mark_capability(struct cheri_bpf_reg_state *reg,
    enum cheri_bpf_cap_source source, uint32_t bounds_id)
{
    reg->kind = CHERI_BPF_VALUE_CAPABILITY;
    reg->source = source;
    reg->bounds_id = bounds_id;
}

static inline bool
cheri_bpf_is_capability(const struct cheri_bpf_reg_state *reg)
{
    return reg->kind == CHERI_BPF_VALUE_CAPABILITY;
}

#endif
