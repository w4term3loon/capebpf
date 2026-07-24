# Workspace Layout

This directory contains the source files mounted into the CheriBSD/Morello VM.
Generated binaries, objects, libraries, and object-JIT artifacts are ignored and
should not be committed.

## Current Test Sources

- `bpf/`: clang-generated eBPF fixtures used by the CHERI JIT ELF-loader suite.
- `test_cheri_generated_bpf.c`: loads generated eBPF ELF objects and runs them
  through the CHERI-aware uBPF JIT.
- `test_cheri_translate_reject.c`: translator accept/reject tests for the CHERI
  backend's supported memory model.
- `exploit_tests.c` and `exploit_programs.h`: handwritten verifier-invalid
  exploit-shaped programs used as baseline/security checks.
- `test42.c`, `test_m2.c`, `test_m2_jmp.c`: small host and purecap smoke tests
  for scalar execution and jumps.

## Retained Diagnostics

The remaining `test_*.c` files are retained development diagnostics for earlier
JIT routes, mmap behavior, loader-backed code, object-backed code, and Morello
capability behavior. They are useful for audit history and debugging but are not
the primary thesis path. Prefer the Makefile targets and `docs/README.md` when
reproducing current results.
