# Primary Research Data Index

This directory contains captured outputs from the CHERI JIT prototype
experiments on CheriBSD purecap QEMU Morello. These are the raw data
points referenced in the thesis evaluation section.

## Documents

### `baseline_results.md`
Output of `test42` (the `r0=42;exit` baseline) on purecap.
Validates Milestone 0 and 1.

### `m2_scalar_alu_results.md`
Output of `test_m2` (7 scalar ALU tests) on both purecap and x86_64.
Validates Milestone 2.

### `exploit_testbench_results.md`
Output of `exploit_tests` (3 verifier-bypass exploit programs) on both
x86_64 (non-capability baseline) and purecap (CHERI JIT). Demonstrates
the differential: x86_64 JIT silently passes all exploits, purecap JIT
traps all exploits with SIGPROT.

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

All tests can be reproduced with:

```
make compile-exploit-tests && make run-exploit-tests   # exploit testbench
make compile-m2-tests && make run-m2-tests             # scalar ALU
```

The instruction matrix test is not yet in the Makefile but can be
built and run manually:
```
docker exec thesis-workspace clang --config ... -o /workspace/test_instruction_matrix /workspace/test_instruction_matrix.c
docker exec thesis-workspace scp -P 2222 /workspace/test_instruction_matrix root@localhost:/root/
docker exec thesis-workspace ssh -p 2222 root@localhost /root/test_instruction_matrix
```