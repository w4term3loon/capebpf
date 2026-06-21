# CHERI JIT Port Base

This file is the implementation contract for the first JIT port.

## Objective

Make memory safety visible in the generated machine code. If an eBPF program
uses a bounded pointer-like value and reaches an out-of-bounds access, Morello
must raise a capability exception.

## Register Model

Each eBPF register has a value kind:

| eBPF value | Native representation | Rule |
| --- | --- | --- |
| scalar | 64-bit integer register | Normal ALU operations are allowed. |
| capability | CHERI capability register | May authorize memory access. |

Do not store every eBPF register only as a capability. eBPF mixes integers and
pointers freely, and treating scalars as capabilities will either lose tags or
produce invalid authority.

Capability roots:

- `ctx`: bounded to the context object passed to the program
- `stack`: bounded to the eBPF stack
- `map_value`: bounded to one map value
- `helper_return`: bounded by the helper shim that produced it

The JIT may derive a narrower capability from a root. It must not create a valid
capability from an arbitrary integer.

## Memory Emission

Use capability-authorized data load/store instructions for normal eBPF memory
operations. Use `CLC` and `CSC` only when the value being loaded or stored is a
capability, for example when spilling a capability register.

Required behavior:

- in-bounds access through a capability succeeds
- out-of-bounds access through a capability traps
- scalar-as-pointer access is rejected by the JIT or traps through an untagged
  capability
- partial overwrite of a spilled capability must not be treated as a valid
  capability reload

## Prologue

The first prologue can be small:

1. Build a bounded context capability for eBPF `R1`.
2. Build a bounded stack capability for eBPF `R10`.
3. Keep scalar scratch registers separate from capability scratch registers.
4. Leave PCC/DDC narrowing as a later coarse-sandbox step unless it is needed
   for the first tests.

## Helper Shims

Helpers that return memory must return bounded capabilities to the JIT path.
The first shim only needs:

- base address
- object size
- permissions
- null result handling

The CVE-2021-4204 pattern depends on this boundary: the helper ABI must not
allow an unchecked raw pointer to regain ambient authority.

## CVE-Pattern Tests

The tests should prove patterns, not reproduce a full Linux exploit chain.

`CVE-2023-2163` pattern:

- construct pointer plus attacker-controlled offset
- make the baseline path reach an out-of-bounds memory operation
- require the CHERI JIT path to trap on the bounded capability

`CVE-2021-4204` pattern:

- pass a bounded object to a helper-like function
- make the helper path attempt access beyond the true object size
- require the CHERI helper shim/JIT path to trap

## First Code Touches

When `workspace/ubpf` is checked out:

1. Copy the existing arm64 JIT backend to a separate CHERI backend.
2. Add register-state tracking from `workspace/cheri_jit_contract.h`.
3. Port only `mov`, `add/sub` on scalars, `exit`, stack load/store, and
   context load/store first.
4. Add tests before adding helper calls.
