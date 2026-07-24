# Primary Research Data Index

This directory contains captured outputs and audit notes for the CHERI JIT prototype. Older result files are research notes from CheriBSD purecap QEMU Morello sessions; `project_state.md` is the current checkout audit and should be read first. Treat older markdown claims as historical notes unless they are repeated in the current audit.

## Documents

### `project_state.md`
Current audit of remotes, verified host and CHERI tests, implementation gaps, and next steps.

### `cheri_direct_jit_repro.md`
Passing raw anonymous mmap direct-JIT repro. It records the C64-entry bug that
made in-bounds generated loads trap with `PROT_CHERI_TAG`, and the current fix:
enter anonymous Morello code through an odd/capmode function address before
sealing/calling it.

### `cheri_direct_mmap_jit_milestone.md`
Current milestone note for the true anonymous mmap CHERI JIT route. This is the
primary non-helper/non-loader path for the narrow supported context-load subset.

### `cheri_loader_jit_repro.md`
Passing loader-backed direct-code sanity check. Loaded purecap code performs the
memory operation directly and gets an in-bounds/OOB CHERI bounds differential.

### `cheri_objjit_context_repro.md`
Passing generated object-backed CHERI JIT proof for `r0 = *(u64 *)(r1 + offset);
exit`. This is retained as fallback/reference evidence; `run-cheri-objjit-compile`
now exercises the default direct mmap CHERI JIT unless `UBPF_CHERI_USE_OBJJIT=1`
is set.

### `generated_bpf_cheri_jit_milestone.md`
Milestone note for the permanent C-to-BPF-to-CHERI-JIT path. Explains why the
fixture exists, what clang emits, which CHERI JIT backend support was needed for
stack register offsets, and what the passing generated-BPF test proves.

### `slides-poc/`
Static interactive slide proof of concept for the thesis presentation. It
contains a browser-openable deck with a pipeline view, an interactive CHERI
bounds visualization, generated-BPF context, and CVE-style result summary.

### `baseline_results.md`
Output of `test42` (the `r0=42;exit` baseline) on purecap.
Validates Milestone 0 and 1.

### `m2_scalar_alu_results.md`
Output of `test_m2` (7 scalar ALU tests) on both purecap and x86_64.
Validates Milestone 2.

### `exploit_testbench_results.md`
Output of `exploit_tests` (3 verifier-bypass exploit programs) on both
x86_64 (non-capability baseline) and purecap (CHERI JIT). The current
single-user VM runner reverified that all three local CVE-shaped cases are
blocked under the CHERI path.

### `instruction_matrix_results.md`
Systematic test of every instruction category from mmap'd PROT_EXEC
memory on QEMU Morello purecap. Identifies the W^X root cause: ALL
load/store instructions crash from executable pages, regardless of
the destination page permissions or base register.

### `jit_bytecode_dump.md`
Raw hex dump of the JIT-generated machine code for the stack store/load
program, with instruction-by-instruction analysis of what works and
what crashes. Shows the M3 decoupled stack mapping design in action.

## Reproduction

The current reproducible CHERI runtime path uses the single-user VM runner:

```sh
sg docker -c 'make cheri-check'                       # passing CHERI translator fail-closed test
sg docker -c 'make cheri-mitigations'                 # passing helper-mediated fallback proof
sg docker -c 'make run-cheri-loader-jit-repro'        # passing loader-backed direct-code proof
sg docker -c 'make run-cheri-objjit-context-repro'    # passing generated object-backed JIT proof
sg docker -c 'make run-cheri-objjit-compile'          # passing uBPF compile integration for direct mmap CHERI JIT context/stack path, including width coverage
sg docker -c 'make run-cheri-generated-bpf'           # passing host clang-generated BPF ELF through CHERI JIT
sg docker -c 'make run-cheri-direct-jit-repro'        # passing raw mmap/C64-entry diagnostic
```

Older SSH-based reproduction snippets below are historical and depend on multi-user SSH, which is currently blocked by the guest hanging at `Starting devd.`. Prefer the single-user runner targets above. The instruction matrix test is not yet in the Makefile but can be built manually if SSH is restored:
```
docker exec thesis-workspace clang --config ... -o /workspace/test_instruction_matrix /workspace/test_instruction_matrix.c
docker exec thesis-workspace scp -P 2222 /workspace/test_instruction_matrix root@localhost:/root/
docker exec thesis-workspace ssh -p 2222 root@localhost /root/test_instruction_matrix
```