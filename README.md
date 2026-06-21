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

See [JIT_PORT.md](JIT_PORT.md) for the minimal implementation contract and
[JIT_PLAN.md](JIT_PLAN.md) for the implementation sequence.

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
make start-vm
make compile-ubpf
make compile-ubpf-test
make run BIN=ubpf_test
```

Purecap OOB smoke test:

```sh
make compile SRC=test.c BIN=test_binary
make run BIN=test_binary
```

`test_binary` is expected to fault in CHERI purecap mode. If it reaches the
final print, the smoke test failed.

Host-side eBPF bytecode build:

```sh
make compile-bpf SRC=my_prog.c BIN=my_prog.o
```

## Current Status

Done:

- Morello/CheriBSD container and VM workflow.
- Purecap C compile/run path.
- uBPF baseline test harness file.
- Minimal JIT-port contract.

Next:

- Check out uBPF and build the baseline interpreter/JIT.
- Add the CHERI-aware JIT backend skeleton.
- Add CVE-pattern tests for CVE-2023-2163 and CVE-2021-4204.
- Add a harness that treats a CHERI capability exception as the expected secure
  result.
