# Roadmap

Current status: Phase 1 done, Milestone 1 (backend skeleton) done,
Milestone 2 (scalar ALU) done. M3 (bounded stack) is blocked by a
QEMU Morello limitation — see notes below.

## MVP Claim

For selected CVE-shaped eBPF memory-safety failures, a CHERI-aware uBPF JIT
traps the illegal memory access at runtime when the same access would otherwise
reach native execution.

## Non-goals

- Do not replace the whole Linux eBPF verifier.
- Do not port the full Linux kernel eBPF subsystem.
- Do not claim temporal safety unless allocator/revocation support is actually
  implemented.
- Do not model every helper. Implement only the helpers needed by the CVE tests.

## Phase 1: Environment

- [x] Study CVE-2023-2163 and CVE-2021-4204 at the pattern level.
- [x] Set up CHERI/Morello toolchain with Docker and QEMU.
- [x] Add Makefile workflow for compile, VM boot, copy, and run.
- [x] Add purecap OOB smoke test.
- [x] Add uBPF interpreter/JIT smoke test source.

## Phase 2: JIT Base

- [x] Check out and build the uBPF submodule.
- [x] Verify baseline uBPF interpreter and stock JIT on CheriBSD purecap.
- [x] Add a separate CHERI-aware arm64/Morello JIT backend.
- [x] Milestone 1: `mov imm` + `exit` run through the CHERI JIT on purecap.
- [x] Milestone 2: Scalar ALU (`mov reg`, `add/sub` imm+reg) — tested and
      matching the interpreter on both x86_64 and purecap.
- [ ] Track each eBPF register as either scalar or capability.
- [ ] Preserve capability provenance across pointer arithmetic, spills, reloads,
      and helper returns.
- [ ] Emit capability-authorized data loads/stores for pointer-based memory
      access.
- [ ] Use `CLC`/`CSC` only when loading or storing capabilities themselves.

> **Milestone 3 (bounded stack) is currently blocked**: any store/load
> instruction executed from mmap'd PROT_EXEC memory crashes with SIGPROT
> on QEMU Morello. Next step is to investigate separating the eBPF stack
> allocation (RW only, not executable) from the JIT code page, or fall
> back to the coarse DDC sandboxing allowed by the Stop Conditions.

## Phase 3: CVE-Pattern Tests

- [ ] CVE-2023-2163 pattern: verifier/path-pruning confusion lets a pointer
      offset escape its real object bounds.
- [ ] CVE-2021-4204 pattern: helper argument checking misses the true memory
      object size.
- [ ] Add minimal helper shims that return bounded capabilities.
- [ ] Add a test harness that records "capability exception" as pass.

## Phase 4: Evaluation

- [ ] Compare interpreter, stock JIT, and CHERI JIT.
- [ ] Measure execution latency and JIT compile time.
- [ ] Report compatibility breaks caused by CHERI alignment/provenance rules.
- [ ] State exactly which verifier responsibilities remain in software.

## First Implementation Target

Implement only enough bytecode support to run:

1. `r0 = 42; exit`
2. stack load/store within bounds
3. stack load/store out of bounds
4. context/map-value access within bounds
5. context/map-value access out of bounds

That is the base needed before attempting the CVE-pattern programs.
