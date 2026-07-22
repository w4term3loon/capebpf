# CHERI-eBPF JIT Prototype

This repository is a small research prototype for testing one claim:

> A CHERI-aware eBPF JIT can turn selected verifier-missed spatial memory bugs
> into deterministic hardware traps.

The project does not try to replace the whole Linux eBPF verifier. The verifier
still owns program admission, termination, helper policy, type rules, and
control-flow restrictions. The CHERI JIT is a second enforcement layer for
memory accesses that reach execution.

## Scope

The MVP uses uBPF on CheriBSD/Morello instead of the in-kernel Linux eBPF
runtime. That keeps the experiment small while preserving the part we need to
study: bytecode is JIT-compiled, then memory operations execute as native
Morello instructions.

The thesis result should be phrased narrowly:

1. Reproduce CVE-shaped eBPF memory-safety failures in a controlled uBPF
   harness.
2. Run the same bytecode through a baseline JIT and a CHERI-aware JIT.
3. Show that the CHERI-aware JIT traps the illegal memory access before it can
   escape the bounded object.
4. Measure the cost of the capability-aware path.

## JIT Rules

The port is not a mechanical `X0-X10` to `C0-C10` rewrite.

- Scalar eBPF values stay as 64-bit integer values.
- Pointer-like eBPF values are represented as CHERI capabilities.
- The JIT must never fabricate a valid capability from an integer.
- Capabilities may only be derived from known roots: context, stack, map value,
  or helper return.
- Data loads/stores should use capability-authorized data load/store
  instructions.
- `CLC`/`CSC` are for loading/storing capabilities themselves, such as
  capability spills. They are not the replacement for every normal data
  `LDR`/`STR`.
- Helper functions that cross a raw-pointer ABI need shims that return bounded
  capabilities.

See [JIT_PORT.md](JIT_PORT.md) for the minimal implementation contract,
[JIT_PLAN.md](JIT_PLAN.md) for the implementation sequence, and
[docs/project_state.md](docs/project_state.md) for the current audited state.

## Repository

```text
.
|-- Dockerfile            CheriBSD + Morello QEMU SDK image
|-- Makefile              Build, VM, compile, and run targets
|-- JIT_PLAN.md           Feasible CHERI JIT implementation sequence
|-- JIT_PORT.md           Minimal CHERI JIT port contract
|-- PLAN.md               Current roadmap
|-- proposal.pdf          Thesis proposal artifact
`-- workspace/
    |-- cheri_jit_contract.h  Small register-state contract for the port
    |-- test.c                Purecap OOB smoke test
    |-- ubpf_test.c           uBPF interpreter/JIT baseline smoke test
    `-- ubpf/                 uBPF git submodule
```

## Quick Start

```sh
git submodule update --init --recursive
make init
make host-check
make cheri-check
```

Experimental direct-JIT checks, now passing for the restricted mmap/C64 context and stack memory path:

```sh
sg docker -c 'make run-cheri-direct-jit-repro'
sg docker -c 'make run-cheri-objjit-compile'
```

Helper-mediated mitigation proof retained as a fallback/reference route. This
runs a shape-specific generated-code stub that tail-calls compiled purecap
helper code for the actual bounded load:

```sh
make cheri-mitigations
```

Purecap one-off run:

```sh
make compile SRC=test.c BIN=test_binary
make run BIN=test_binary
```

`make run` boots the CheriBSD image in single-user mode, mounts `/workspace`
through 9p, runs `/mnt/$(BIN)`, and powers the VM down. This avoids the current
multi-user `devd` hang in the Morello image.

Host-side eBPF bytecode build:

```sh
make compile-bpf SRC=my_prog.c BIN=my_prog.o
```

## Current Status

The submodule is initialized and host-side baseline tests are wired through
`make host-check`. In this checkout, the x86_64 interpreter/JIT baseline works
for `r0=42`, scalar ALU, and conditional jumps. The host exploit harness also
confirms that verifier-invalid programs can pass through the non-capability JIT.

The CHERI backend exists in the uBPF submodule and should currently be read as
a narrow object-bounds prototype, not as a completed eBPF verifier replacement.
Unsupported context stores, capability stores, local calls, atomics, and
untracked scalar-pointer loads are rejected during CHERI translation. The
supported path carries the `R1` context pointer and `R10` stack pointer as
CHERI capabilities through direct anonymous mmap JIT code; in-bounds
context/stack scalar memory accesses return successfully, out-of-bounds
accesses trap under CHERI bounds, and uninitialized stack scalar reads return
zero from the cleared bounded stack. The old helper/object routes remain as
fallback evidence, but the primary route is now the direct mmap JIT entered in
Morello C64 mode.

Purecap results in `docs/` are retained as captured research notes. The latest
audit verified Docker initialization, purecap compilation, x86_64 host tests,
host-side CHERI translation rejection tests, purecap CHERI scalar execution, direct mmap CHERI context/stack memory tests, and CHERI translation through
the single-user VM runner. Multi-user SSH startup is still blocked by the
CheriBSD guest hanging at `Starting devd.`. See [docs/project_state.md](docs/project_state.md) for the current verified state and next steps.
