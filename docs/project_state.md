# Project State Audit - 2026-07-21

This document separates what this checkout proves from what the older roadmap and result notes claim. The thesis plan in `proposal.pdf` is treated as the source of intent; older markdown result files are treated as historical notes unless reverified here.

## Repository Identity

- Root remote: `git@github.com:w4term3loon/capebpf.git`
- uBPF submodule remote: `git@github.com:w4term3loon/ubpf.git`
- uBPF submodule commit: `fe22e8c822ed470bf29d23ff71d3cc04610a3b8a`

## Verified Now

Docker works in this session through `sg docker`; the current shell still does not directly see the refreshed `docker` group. The Morello container and single-user CheriBSD runner are usable.

Passing checks:

```sh
make host-check
sg docker -c 'make cheri-check'
sg docker -c 'make cheri-mitigations'
sg docker -c 'make run-cheri-loader-jit-repro'
sg docker -c 'make run-cheri-objjit-context-repro'
sg docker -c 'make run-cheri-objjit-compile'
sg docker -c 'make run-exploit-tests'
```

Observed state:

- Host x86_64 baseline works for `test42`, scalar ALU, conditional jumps, and the non-capability exploit harness.
- `make cheri-check` boots CheriBSD single-user, mounts `/workspace` via 9p, and runs the CHERI translator rejection harness.
- Basic purecap CHERI JIT execution works for scalar bytecode: interpreter and JIT both return `42`.
- The CHERI backend now rejects context stores, capability stores, atomics, local calls, and loads from untracked scalar pointers at translation time instead of compiling unsafe memory operations.
- The CHERI backend accepts a restricted capability-memory subset: scalar loads through the `R1` context capability or tracked context aliases, and scalar stack loads/stores through the bounded `R10` stack capability or tracked stack aliases.
- Simple `MOV64_REG` and 64-bit immediate `ADD/SUB` preserve context/stack capability provenance, so common forms such as `r6 = r1; r6 += 8; load` and `r2 = r10; r2 += -16; store/load` now execute through hardware capabilities.
- The CHERI backend now runs a conservative control-flow register-kind analysis before emission: at branch joins, a register remains a capability only if all reaching paths agree on the same capability kind; mixed scalar/capability joins are treated as scalar and later capability memory access is rejected.
- The CHERI backend tracks `R10` as a stack-capability kind and rejects programs that try to return a capability-kind value in `R0`; this deliberately blocks the pointer-leak exploit pattern at translation time.
- `make cheri-mitigations` proves the first useful in-bounds/out-of-bounds differential for a context load: generated code tail-calls a compiled purecap helper for the actual memory access, the in-bounds load returns the expected value, and the out-of-bounds load traps with CHERI signal 34.
- `make run-cheri-loader-jit-repro` proves a direct loaded-code spatial differential without a helper-mediated load: in-bounds returns the expected value, OOB traps with `PROT_CHERI_BOUNDS`.
- `make run-cheri-objjit-context-repro` strengthens that into generated object-backed JIT evidence: raw eBPF bytes for `r0 = *(u64 *)(r1 + offset); exit` are parsed into generated Morello assembly, which returns in-bounds and traps OOB with `PROT_CHERI_BOUNDS`.
- `make run-cheri-objjit-compile` now exercises the default direct anonymous mmap CHERI JIT through the uBPF-facing `ubpf_load()`/`ubpf_compile()` flow for context loads, context aliases, context immediate pointer arithmetic, branch-preserved context capabilities, stack scalar store/load, stack immediate pointer arithmetic, uninitialized stack reads, and stack/context OOB traps. It returns a capmode sentry for the generated mapping, returns expected in-bounds values, traps spatial OOB accesses with `PROT_CHERI_BOUNDS`, and rejects a branch join where one path scalar-clobbers a context capability alias.
- `make run-exploit-tests` currently reports all three local CVE-shaped harness cases as covered under the CHERI path: OOB context read traps, pointer return is compile-blocked by register-kind policy, and uninitialized stack read is mitigated by returning zero from the cleared bounded stack.
- The CHERI backend now has a proper first purecap prologue/epilogue: it saves/restores C29/C30 as capabilities, derives a bounded `r10` eBPF stack capability, clears the eBPF stack before execution, and rejects local function calls instead of emitting incomplete scalar stack-spill code.

## Resolved Direct mmap Experiment

The standalone direct-JIT repro now captures a resolved blocker outside uBPF:

```sh
sg docker -c 'make run-cheri-direct-jit-repro'
```

That repro emits compiler-verified bytes for `ldr x0, [c0, #8]; ret c30` into anonymous executable memory. The earlier in-bounds trap was caused by entering generated code without Morello C64 state. CheriBSD derives C64 entry from bit 0 of the target address, so the direct JIT now calls/seals `(uintptr_t)code | 1`. After that fix, in-bounds generated loads return `0xfeedfacecafebeef`, out-of-bounds generated loads trap with `PROT_CHERI_BOUNDS`, and the uBPF compile integration uses the same capmode-entry rule. See `docs/cheri_direct_jit_repro.md` and `docs/cheri_direct_mmap_jit_milestone.md`.

## Current JIT-Only Route

The primary JIT-only route is now direct anonymous mmap code entered in C64 mode. It supports the current restricted context/stack capability-memory subset through the uBPF compile API:

```sh
sg docker -c 'make run-cheri-objjit-compile'
```

Despite the old target name, this uses the default direct mmap CHERI JIT unless `UBPF_CHERI_USE_OBJJIT=1` is set. It proves in-bounds and OOB behavior for context loads, context aliases, context immediate pointer arithmetic, stack stores/loads through `R10`, stack immediate pointer arithmetic, and zeroed uninitialized stack reads.

`run-cheri-loader-jit-repro` and `run-cheri-objjit-context-repro` remain useful fallback/reference evidence because they independently prove that loaded purecap code can perform the same bounded memory operation. They are no longer the primary implementation route.

## Current Mitigation Path

`run-cheri-tail-helper-context` is retained as a targeted fallback/reference proof for helper-mediated memory enforcement:

```sh
sg docker -c 'make run-cheri-tail-helper-context'
```

It compiles only a tiny uBPF-shaped program class:

- `r0 = *(u64 *)(r1 + offset)`
- `exit`

The generated code does not execute the data load itself. Instead, it arranges a custom purecap calling convention and tail-calls a normal compiled C helper:

- generated code receives a helper capability, memory capability, and memory length;
- generated code moves those arguments into the helper ABI registers;
- generated code branches through the helper capability with `br c3`;
- compiled purecap helper code performs `*(uint64_t *)((char *)mem + offset)`.

This is not yet integrated into `ubpf_compile`, and it is not yet a general eBPF memory model. It remains useful fallback evidence: compiled purecap helper code can perform the bounded memory operation successfully for an in-bounds object and fault for an out-of-bounds offset. The primary route is now direct mmap-generated code, not helper mediation.

## Implementation Changes In This Pass

- Added `tools/cheri_vm.py`, a deterministic single-user Morello VM runner using cheribuild's vendored `pexpect`.
- Reworked CHERI run targets to mount `/workspace` through 9p and run binaries from the serial console instead of SSH.
- Removed the Dockerfile `apt-get` dependency and added a small `pkg-config --modversion libarchive` compatibility wrapper for cheribuild's startup check.
- Fixed VM launch targets to run cheribuild as `cheri` while keeping container compile steps writable.
- Added host and purecap CHERI translation tests.
- Added a minimal CHERI register-kind tracker in the arm64 CHERI backend: `R1` starts as a context capability; scalar writes clear capability state; `mov` propagates state.
- Changed the CHERI backend to reject unsupported memory operations during translation.
- Added experimental context-load runtime coverage; the direct mmap/C64 path now returns in-bounds values and traps out-of-bounds values.
- Cleaned the exploit harness so purecap runs compare `Interpreter`, `Stock JIT`, and `CHERI JIT` without a duplicate generic JIT column.
- Updated the exploit harness so CHERI translation rejection is reported as `blocked`, not as a generic error.
- Fixed the JIT allocator to request explicit `PROT_CAP`, reserve `PROT_MAX(RWX+CAP)` at mmap time under purecap, narrow generated code pages to RX+CAP with `mprotect` after copying, and keep the raw mapping base separate from the callable sentry.
- Tested low-complexity generated-code mapping variants (`PROT_CAP`, `PROT_MAX`, sentries, file-backed RX mappings, `PROC_PROTMAX`, and W+X process controls); these showed the mapping was not the core blocker.
- Added `test_cheri_direct_jit_repro.c`, a now-passing repro proving anonymous mmap code must be entered through a capmode address (`addr | 1`) and then gets the intended in-bounds/OOB CHERI bounds differential.
- Tested helper transfer patterns; direct branches to compiled helper code still run under the generated-code PCC and trap, while a capability-register tail call to the helper succeeds.
- Added `test_cheri_tail_helper_context.c` and `cheri-mitigations` to capture the working helper-mediated bounded-load proof.
- Added `cheri_loader_jit_payload.c`, `test_cheri_loader_jit_repro.c`, and `run-cheri-loader-jit-repro` to capture the passing loader-backed direct-code proof.
- Added `tools/cheri_objjit_emit.py`, `test_cheri_objjit_context_repro.c`, and `run-cheri-objjit-context-repro` to capture the generated object-backed direct-JIT context-load proof.
- Added an integrated CHERI direct mmap JIT compile path in uBPF for `LDXDW r0, [r1+offset]; EXIT` and `MOV64_REG rN, r1; LDXDW r0, [rN+offset]; EXIT`; the older object-backed path is now opt-in via `UBPF_CHERI_USE_OBJJIT=1`.
- Replaced the temporary minimal CHERI prologue with a first proper purecap frame setup: C29/C30 capability save/restore, bounded `r10` stack capability derivation, eBPF stack zeroing, and fail-closed rejection for local calls.
- Added stack scalar load/store lowering through tracked stack capabilities, while rejecting context stores and attempts to store capability-kind values.
- Added capability-preserving 64-bit immediate pointer arithmetic for tracked context/stack capabilities.
- Added conservative control-flow register-kind analysis so branch joins meet capability provenance before emission.
- Updated `test_cheri_objjit_compile.c` and `run-cheri-objjit-compile` to prove the direct mmap CHERI JIT path works through `ubpf_load()`/`ubpf_compile()` despite the historical target name.
- Tightened `run-exploit-tests` so purecap runs fail if the CHERI path misses a harness case; the uninitialized-stack case is now classified as mitigated only when it returns the known zero from the cleared stack.
- Added `host-check` and tightened the host uBPF build so it compiles host-relevant sources only.
- Removed generated binaries from source control and added them to `.gitignore`.

## Feasibility Assessment

The proposal is feasible as a staged research prototype, but the credible thesis claim must stay narrower than the older markdown suggests.

What is feasible now:

- Use uBPF on CheriBSD/Morello as a controlled user-space stand-in for studying JIT memory safety.
- Demonstrate that unsupported JIT memory operations fail closed at translation time.
- Demonstrate that the current CHERI JIT path covers all three local exploit-harness cases, with important caveats: pointer leakage is blocked by explicit register-kind policy, uninitialized stack disclosure is mitigated by stack zeroing rather than full verifier stack-state analysis, and OOB context/stack memory has proven direct-JIT `PROT_CHERI_BOUNDS` differentials for the supported shapes.
- Demonstrate a credible JIT-only route for context and stack scalar memory using anonymous mmap-generated Morello code: generated code performs memory operations directly and gets in-bounds success/OOB bounds traps through the uBPF-facing compile API.
- Keep the helper-mediated route as a fallback: leave scalar/control-flow code in generated JIT memory, but lower capability memory operations into compiled purecap helper shims that preserve object bounds.
- Continue toward a capability-aware JIT one root at a time: context first, then stack, then helper/map returns.

What is not proven yet:

- That the current result generalizes beyond the supported context/stack scalar-memory shapes.
- That the helper-tail-call proof is equivalent to a full JIT. It currently proves one final context-load shape, not arbitrary eBPF memory programs.
- That helper-returned pointers, maps, local calls, atomics, capability spills, or full verifier-grade path-sensitive scalar reasoning are protected by a completed scalar/capability register contract.

The raw mmap direct-JIT blocker was resolved by entering generated code in Morello C64 mode (`addr | 1`) before creating/calling the entry capability. The current non-helper path is now the preferred route; the helper/object-mediated route remains only as fallback/reference.

## Recommended Next Steps

1. Expand stack/context memory width coverage (`B`, `H`, `W`, `DW`, signed loads) through the same capability-memory helper.
2. Add helper-returned pointer or map-value capability roots next; keep helper/map memory rejected until returned bounds and provenance are explicit.
3. Add more branch/regression cases around loops and joins as new pointer roots are introduced.
4. Keep helper-mediated and object-backed context-load lowering as fallback/reference routes only.
5. Keep exploit tests classified by mechanism: spatial OOB bounds trap, pointer leakage policy reject, and non-spatial uninitialized-stack disclosure mitigated by zeroing.
6. Keep `make host-check`, `sg docker -c 'make cheri-check'`, `sg docker -c 'make cheri-mitigations'`, `sg docker -c 'make run-cheri-loader-jit-repro'`, `sg docker -c 'make run-cheri-objjit-context-repro'`, `sg docker -c 'make run-cheri-direct-jit-repro'`, `sg docker -c 'make run-cheri-objjit-compile'`, and `sg docker -c 'make run-exploit-tests'` green.
