# Generated BPF x86 vs CHERI JIT Comparison

This report records the current side-by-side generated-BPF evidence path:

```text
C fixture -> clang -target bpf -> ELF eBPF object -> uBPF ELF loader
```

The same generated ELF objects are then run through:

- host x86_64 uBPF JIT, without capabilities;
- CheriBSD/Morello purecap uBPF CHERI JIT, with bounded context, stack, and
  opt-in helper-returned map-value capabilities.

The shared case manifest is `workspace/generated_bpf_cases.h`. The host
baseline harness is `workspace/test_generated_bpf_host.c`; the CHERI harness is
`workspace/test_cheri_generated_bpf.c`.

## Reproduction

```sh
make run-generated-bpf-host
sg docker -c 'make run-cheri-generated-bpf'
```

The combined convenience target is:

```sh
sg docker -c 'make generated-bpf-comparison'
```

The host baseline intentionally passes 16-byte logical eBPF context/map objects
backed by an 8192-byte native allocation. This makes out-of-bounds reads
deterministic on x86 by placing a sentinel value at offset 4096. It does not
make the access safe; it only prevents the baseline from depending on accidental
segfaults.

## Latest Result

Verified on 2026-07-24.

| Case | CVE relevance | Host x86_64 uBPF JIT | CHERI uBPF JIT | Result |
| --- | --- | --- | --- | --- |
| `stack_array` | positive control | returned `0x6a` | returned `0x6a` | valid program preserved |
| `branch_stack` | positive control | returned `0x24` | returned `0x24` | valid program preserved |
| `stack_widths` | positive control | returned `0x64` | returned `0x64` | valid program preserved |
| `context_in_bounds` | positive control | returned `0x3000` | returned `0x3000` | valid program preserved |
| `branch_context_in_bounds` | positive control | returned `0x2000` | returned `0x2000` | valid program preserved |
| `arithmetic_context_in_bounds` | positive control | returned `0x2000` | returned `0x2000` | valid program preserved |
| `helper_map_read_in_bounds` | positive control | returned `0x2000` | returned `0x2000` | valid generated helper/map read preserved |
| `helper_map_write_in_bounds` | positive control | returned `0x5a` | returned `0x5a` | valid generated helper/map write/read preserved |
| `context_oob` | CVE-2020-8835-style range-analysis OOB | returned `0xfeedfacecafebeef` | `SIGPROT` / `PROT_CHERI_BOUNDS` | unsafe baseline, hardware bounds trap under CHERI |
| `branch_context_oob` | CVE-2023-2163-style unsafe path/pruning OOB | returned `0xfeedfacecafebeef` | `SIGPROT` / `PROT_CHERI_BOUNDS` | unsafe baseline, hardware bounds trap under CHERI |
| `arithmetic_context_oob` | CVE-2021-3490/CVE-2021-31440-style arithmetic OOB | returned `0xfeedfacecafebeef` | `SIGPROT` / `PROT_CHERI_BOUNDS` | unsafe baseline, hardware bounds trap under CHERI |
| `stack_oob` | CVE-2017-16995-style bad-offset memory corruption analogue | returned `0x5a` | `SIGPROT` / `PROT_CHERI_BOUNDS` | unsafe baseline, hardware bounds trap under CHERI |
| `helper_map_read_oob` | CVE-2021-4204-style helper/map OOB read analogue | returned `0xfeedfacecafebeef` | `SIGPROT` / `PROT_CHERI_BOUNDS` | unsafe baseline, hardware bounds trap under CHERI |
| `helper_map_write_oob` | CVE-2021-4204-style helper/map OOB write analogue | returned `0x0` after executing write | `SIGPROT` / `PROT_CHERI_BOUNDS` | unsafe baseline, hardware bounds trap under CHERI |

Summary:

- valid generated-BPF programs: `8/8` returned expected values on both JITs;
- generated-BPF OOB programs: `6/6` executed unsafely on host x86_64 uBPF JIT;
- generated-BPF OOB programs: `6/6` trapped with CHERI bounds under the purecap
  CHERI JIT.

## Proposal CVEs

The proposal explicitly names CVE-2023-2163 and CVE-2021-4204.

`CVE-2023-2163` is represented by `branch_context_oob`. This is a reduced
analogue, not a full Linux exploit reproduction: it models the final safety
failure where an unsafe branch/path reaches an out-of-bounds memory access. The
important result is that the non-capability JIT executes the unsafe access,
while the CHERI JIT reaches the memory instruction and receives a hardware
`PROT_CHERI_BOUNDS` trap.

`CVE-2021-4204` is represented by `helper_map_read_oob` and
`helper_map_write_oob`. This is also a reduced analogue, not a full Linux
ring-buffer exploit reproduction: it models the final safety failure where a
helper-returned memory root is used with an invalid offset. The current fixture
is compiler-generated BPF and is backed by the opt-in helper/map capability root
documented in `docs/helper_map_capability_milestone.md`.

## Additional Strong CVE Analogues

From the earlier CVE exploration, the strongest current generated-BPF additions
are:

| CVE | Current coverage | Why it is useful |
| --- | --- | --- |
| CVE-2020-8835 | `context_oob` | range-analysis failure reduced to a final OOB context access |
| CVE-2021-3490 | `arithmetic_context_oob` | ALU/arithmetic-derived bad offset reduced to a final OOB context access |
| CVE-2021-31440 | `arithmetic_context_oob` | verifier arithmetic/range bug family reduced to final OOB access |

`CVE-2017-16995` is also represented as a medium-strength analogue through
`stack_oob`, because the current fixture models bad-offset stack corruption
rather than the full Linux sign-extension vulnerability.

## What This Proves

This comparison supports a narrow but credible claim:

> For generated eBPF bytecode whose memory accesses are rooted in the tracked
> context, stack, or opt-in helper-returned map-value capabilities, the CHERI JIT
> can preserve valid programs while relying on CHERI hardware to trap spatial
> out-of-bounds accesses that the non-capability uBPF JIT executes unsafely.

The CHERI OOB results are not software pre-checks in the harness. The harness
loads the generated ELF object, compiles it, calls the JIT function, and records
the CheriBSD `SIGPROT` / `PROT_CHERI_BOUNDS` signal raised during execution.

## What This Does Not Prove

This is not a complete verifier replacement:

- full ring-buffer pointer roots and real Linux helper/map semantics are not
  modeled yet; only a narrow opt-in helper-returned map-value root is modeled;
- temporal memory safety is not evaluated here;
- pointer-leak prevention still depends on CHERI JIT register-kind policy, not
  on a bounds trap;
- uninitialized scalar stack reads are mitigated by stack zeroing, not by CHERI
  bounds;
- the CVE tests are reduced analogues, not full Linux kernel exploit ports.

The current result is still useful because it isolates the core thesis claim:
hardware capabilities can enforce spatial memory safety at the final memory
operation even when software reasoning about paths or offsets is wrong.
