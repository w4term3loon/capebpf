# CVE Validation Matrix

This note summarizes the CVE coverage that is currently honest to claim for the
uBPF/CHERI prototype. It uses `proposal.pdf` as the source of truth for the
proposal CVEs and treats the generated markdown notes as supporting material.

## Proposal CVEs

The proposal explicitly names these high-severity eBPF CVEs:

| CVE | Proposal category | Current project coverage | Claim strength |
| --- | --- | --- | --- |
| CVE-2023-2163 | register dependency tracking / path pruning | `branch_context_oob` in the generated-BPF comparison | reduced analogue, verified |
| CVE-2021-4204 | helper argument checking / ring-buffer memory access | `helper_map_read_oob` and `helper_map_write_oob` in the generated-BPF and helper/map suites | reduced analogue, verified |

Neither case is a full Linux kernel exploit port. The project currently tests
the final unsafe memory shape that those bugs enable: a program reaches an
out-of-bounds memory operation after software reasoning failed.

## Additional Strong CVE Analogues

The three strongest additional CVE-style cases from the earlier exploration are:

| CVE | Current fixture | Why it is strong evidence |
| --- | --- | --- |
| CVE-2020-8835 | `context_oob` | range-analysis failure reduced to final OOB access through a bounded context root |
| CVE-2021-3490 | `arithmetic_context_oob` | ALU32/arithmetic-derived bad offset reduced to final OOB access |
| CVE-2021-31440 | `arithmetic_context_oob` | verifier arithmetic/range bug family reduced to final OOB access |

`CVE-2017-16995` is also represented as a medium-strength analogue through
`stack_oob`, but it is less direct because the current fixture models the final
bad-offset stack access rather than the exact Linux sign-extension verifier bug.

## Current Verified Result

The current security evidence is split across two suites:

```sh
sg docker -c 'make generated-bpf-comparison'
sg docker -c 'make helper-map-cap-comparison'
sg docker -c 'make cheri-check'
```

The generated-BPF comparison verifies eight valid compiler-generated eBPF
programs and six OOB programs. The valid programs return the same expected
values on x86_64 and CHERI. The OOB programs execute unsafely on the x86_64 uBPF
JIT and trap with `SIGPROT` / `PROT_CHERI_BOUNDS` on the CHERI JIT.

The helper/map capability suite verifies two valid helper-returned map-value
accesses and two OOB helper/map accesses. The valid accesses return expected
values on both platforms. The OOB read/write cases execute on the x86_64 uBPF
JIT and trap with `PROT_CHERI_BOUNDS` on the CHERI JIT.

## What Is Hardware-Enforced

For the spatial OOB cases, the harness does not perform a software bounds check
before calling the JIT function. The CHERI JIT emits capability-relative memory
operations for tracked context, stack, and opt-in helper-returned map-value
roots. When the effective address is outside the capability bounds, CheriBSD
reports a hardware capability fault. The CVE-2021-4204 helper/map analogue is now
available in compiler-generated BPF form as well as the original hand-encoded
bytecode form.

The relevant observed trap shape is:

```text
SIGPROT / PROT_CHERI_BOUNDS
```

## What Is Still Not Proved

- Full Linux verifier bugs are not reproduced end-to-end.
- Full ring-buffer helper semantics for CVE-2021-4204 are not implemented.
- Generic capability-returning helper ABI support is not implemented.
- Temporal memory safety is not tested.
- Pointer-leak prevention still depends on explicit CHERI JIT register-kind
  policy.
- Uninitialized scalar stack disclosure is mitigated by zeroing, not by CHERI
  bounds.

The credible thesis statement is therefore narrow:

> For supported eBPF memory roots, CHERI can move final spatial bounds
> enforcement from fragile verifier reasoning into hardware, while still
> preserving valid compiler-generated programs.
