# Generated BPF CHERI JIT Milestone

This note records the current compiler-generated eBPF test path:

```text
C fixture -> clang -target bpf -> ELF eBPF object -> uBPF ELF loader -> CHERI JIT -> Morello/CheriBSD
```

The source fixtures live in `workspace/bpf/`. The harness is
`workspace/test_cheri_generated_bpf.c`.

## Reproduction

```sh
make -B compile-generated-bpf
make run-generated-bpf-host
sg docker -c 'make run-cheri-generated-bpf'
sg docker -c 'make cheri-check'
```

`compile-generated-bpf` rebuilds every fixture and prints the eBPF disassembly.
`cheri-check` runs the CHERI translator accept/reject suite and this generated
BPF JIT suite.

## Fixture Set

Positive fixtures should execute normally under CHERI:

| Fixture | Coverage | Expected result |
| --- | --- | --- |
| `stack_array.c` | dynamic bounded stack byte access | `0x6a` |
| `branch_stack.c` | branch-selected stack byte access | `0x24` |
| `stack_widths.c` | stack `u64`, `u32`, and `u16` accesses | `0x64` |
| `context_in_bounds.c` | direct in-bounds context reads | `0x3000` |
| `branch_context_in_bounds.c` | branch-selected in-bounds context read | `0x2000` |
| `arithmetic_context_in_bounds.c` | arithmetic-derived in-bounds context read | `0x2000` |
| `helper_map_read_in_bounds.c` | helper-returned map-value in-bounds read | `0x2000` |
| `helper_map_write_in_bounds.c` | helper-returned map-value in-bounds write/read | `0x5a` |

Negative fixtures should trap under CHERI bounds:

| Fixture | Coverage | Expected result |
| --- | --- | --- |
| `context_oob.c` | direct out-of-bounds context read | `SIGPROT` |
| `branch_context_oob.c` | branch-selected out-of-bounds context read | `SIGPROT` |
| `arithmetic_context_oob.c` | arithmetic-derived out-of-bounds context read | `SIGPROT` |
| `stack_oob.c` | dynamic out-of-bounds stack access | `SIGPROT` |
| `helper_map_read_oob.c` | helper-returned map-value out-of-bounds read | `SIGPROT` |
| `helper_map_write_oob.c` | helper-returned map-value out-of-bounds write | `SIGPROT` |

The harness uses fixed two-word context and helper/map objects:

```c
uint64_t ctx[] = {0x1000ULL, 0x2000ULL};
uint64_t map[] = {0x1000ULL, 0x2000ULL};
```

## Relevant Bytecode Patterns

The in-bounds arithmetic context fixture compiles to capability-plus-scalar
addressing that must stay inside the two-word context capability:

```text
r2 = *(u64 *)(r1 + 0x0)
r2 >>= 0x9
r2 &= 0x8
r1 += r2
r0 = *(u64 *)(r1 + 0x0)
exit
```

The out-of-bounds arithmetic context fixture uses the same kind of pointer
calculation but lands outside the context bounds:

```text
r2 = *(u64 *)(r1 + 0x0)
r2 >>= 0x9
r3 = 0x7ffffffffffff8 ll
r2 &= r3
r1 += r2
r0 = *(u64 *)(r1 + 0xff8)
exit
```

The stack fixtures similarly exercise `r10`-derived stack capabilities. Dynamic
in-bounds stack offsets return normally; dynamic out-of-bounds stack offsets
trap.

## Current Result

Latest verified generated-BPF CHERI JIT metrics:

| Category | Cases | Result |
| --- | ---: | --- |
| Valid generated BPF | 8/8 | returned expected values |
| OOB generated BPF | 6/6 | trapped with `signal=34 code=1(PROT_CHERI_BOUNDS)` |
| Unexpected failures | 0 | none |

This is evidence for selective capability enforcement: the CHERI JIT runs valid
generated BPF and traps generated accesses whose final address violates context,
stack, or opt-in helper-returned map-value capability bounds. The generated-BPF harness does not perform a
pre-execution bounds check for these cases; it calls the JIT function and records
the CheriBSD `SIGPROT`/`PROT_CHERI_BOUNDS` signal raised during execution.

## Limits

This is not a full verifier replacement. The generated suite now covers one
trusted helper-returned map-value shape, but it does not yet cover real Linux map
metadata, ring-buffer helpers, packet pointers, generic helper-returned pointer
types, local calls, or atomics. The side-by-side host/x86 versus CHERI comparison harness now lives
in `workspace/test_generated_bpf_host.c`, and the current report is
`docs/generated_bpf_x86_cheri_comparison.md`.
