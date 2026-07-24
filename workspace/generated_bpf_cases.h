#ifndef GENERATED_BPF_CASES_H
#define GENERATED_BPF_CASES_H

#include <stdint.h>

#ifndef GENERATED_BPF_OBJECT_ROOT
#define GENERATED_BPF_OBJECT_ROOT "workspace/bpf/"
#endif

#define GENERATED_BPF_OBJECT(name) GENERATED_BPF_OBJECT_ROOT name ".o"

enum generated_bpf_expectation {
    EXPECT_RETURN,
    EXPECT_CHERI_TRAP,
};

enum generated_bpf_memory_root {
    GENERATED_ROOT_CONTEXT,
    GENERATED_ROOT_HELPER_MAP,
};

#define GENERATED_BPF_HELPER_MAP_LOOKUP 7
#define GENERATED_BPF_HELPER_MAP_NAME "map_lookup_value"

struct generated_bpf_case {
    const char* name;
    const char* object_path;
    const char* symbol;
    const char* cve_relevance;
    const char* coverage;
    uint64_t expected_result;
    enum generated_bpf_expectation expectation;
    enum generated_bpf_memory_root memory_root;
};

static const struct generated_bpf_case generated_bpf_cases[] = {
    {
        "stack_array",
        GENERATED_BPF_OBJECT("stack_array"),
        "foo",
        "positive control",
        "dynamic bounded stack byte access",
        0x6aULL,
        EXPECT_RETURN,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "branch_stack",
        GENERATED_BPF_OBJECT("branch_stack"),
        "foo",
        "positive control",
        "branch-selected stack byte access",
        0x24ULL,
        EXPECT_RETURN,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "stack_widths",
        GENERATED_BPF_OBJECT("stack_widths"),
        "foo",
        "positive control",
        "stack u64, u32, and u16 accesses",
        0x64ULL,
        EXPECT_RETURN,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "context_in_bounds",
        GENERATED_BPF_OBJECT("context_in_bounds"),
        "foo",
        "positive control",
        "direct in-bounds context reads",
        0x3000ULL,
        EXPECT_RETURN,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "branch_context_in_bounds",
        GENERATED_BPF_OBJECT("branch_context_in_bounds"),
        "foo",
        "positive control",
        "branch-selected in-bounds context read",
        0x2000ULL,
        EXPECT_RETURN,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "arithmetic_context_in_bounds",
        GENERATED_BPF_OBJECT("arithmetic_context_in_bounds"),
        "foo",
        "positive control",
        "arithmetic-derived in-bounds context read",
        0x2000ULL,
        EXPECT_RETURN,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "helper_map_read_in_bounds",
        GENERATED_BPF_OBJECT("helper_map_read_in_bounds"),
        "foo",
        "positive control",
        "compiler-generated helper-returned map-value in-bounds read",
        0x2000ULL,
        EXPECT_RETURN,
        GENERATED_ROOT_HELPER_MAP,
    },
    {
        "helper_map_write_in_bounds",
        GENERATED_BPF_OBJECT("helper_map_write_in_bounds"),
        "foo",
        "positive control",
        "compiler-generated helper-returned map-value in-bounds write/read",
        0x5aULL,
        EXPECT_RETURN,
        GENERATED_ROOT_HELPER_MAP,
    },
    {
        "context_oob",
        GENERATED_BPF_OBJECT("context_oob"),
        "foo",
        "CVE-2020-8835-style range-analysis OOB",
        "direct out-of-bounds context read",
        0,
        EXPECT_CHERI_TRAP,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "branch_context_oob",
        GENERATED_BPF_OBJECT("branch_context_oob"),
        "foo",
        "CVE-2023-2163-style unsafe path/pruning OOB",
        "branch-selected out-of-bounds context read",
        0,
        EXPECT_CHERI_TRAP,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "arithmetic_context_oob",
        GENERATED_BPF_OBJECT("arithmetic_context_oob"),
        "foo",
        "CVE-2021-3490/CVE-2021-31440-style arithmetic OOB",
        "arithmetic-derived out-of-bounds context read",
        0,
        EXPECT_CHERI_TRAP,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "stack_oob",
        GENERATED_BPF_OBJECT("stack_oob"),
        "foo",
        "CVE-2017-16995-style bad-offset memory corruption analogue",
        "dynamic out-of-bounds stack access",
        0,
        EXPECT_CHERI_TRAP,
        GENERATED_ROOT_CONTEXT,
    },
    {
        "helper_map_read_oob",
        GENERATED_BPF_OBJECT("helper_map_read_oob"),
        "foo",
        "CVE-2021-4204-style helper/map OOB read analogue",
        "compiler-generated helper-returned map-value out-of-bounds read",
        0,
        EXPECT_CHERI_TRAP,
        GENERATED_ROOT_HELPER_MAP,
    },
    {
        "helper_map_write_oob",
        GENERATED_BPF_OBJECT("helper_map_write_oob"),
        "foo",
        "CVE-2021-4204-style helper/map OOB write analogue",
        "compiler-generated helper-returned map-value out-of-bounds write",
        0,
        EXPECT_CHERI_TRAP,
        GENERATED_ROOT_HELPER_MAP,
    },
};

#define GENERATED_BPF_CASE_COUNT (sizeof(generated_bpf_cases) / sizeof(generated_bpf_cases[0]))

#endif
