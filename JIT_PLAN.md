# Feasible JIT Port Plan

This is the shortest path to a defensible CHERI-aware uBPF JIT prototype.

## Goal

Build a separate Morello/CHERI JIT backend that can run a small eBPF subset and
prove that bounded capability memory accesses trap selected CVE-shaped
out-of-bounds cases.

Do not start by porting the full Linux JIT. Do not start by supporting every
uBPF opcode. The first backend only needs enough instructions to demonstrate
the safety claim.

## Ground Rules

- Keep the stock uBPF interpreter and stock JIT as baselines.
- Add the CHERI JIT as a separate backend/file.
- Track eBPF register state as `scalar` or `capability`.
- Never convert arbitrary integers into valid capabilities.
- Treat helper shims as part of the trusted test harness.
- Add tests before broadening opcode support.

## Milestone 0: Baseline

Deliverable: uBPF builds and the existing `r0 = 42; exit` test passes.

Steps:

1. Check out `workspace/ubpf`.
2. Build `libubpf.a` with `make compile-ubpf`.
3. Build and run `workspace/ubpf_test.c`.
4. Confirm both interpreter and stock JIT return `42`.

Stop here if the stock JIT does not work on CheriBSD purecap. Fix that before
adding CHERI behavior.

## Milestone 1: Backend Skeleton

Deliverable: a CHERI backend exists but only supports `mov imm` and `exit`.

Steps:

1. Copy the uBPF arm64 JIT backend to a new CHERI backend file.
2. Add a compile switch or explicit entry point for the CHERI backend.
3. Add `workspace/cheri_jit_contract.h` state tracking.
4. Emit only:
   - `BPF_MOV | BPF_K`
   - `BPF_EXIT`
5. Re-run the `r0 = 42; exit` test through the CHERI backend.

Definition of done: interpreter, stock JIT, and CHERI JIT all return `42`.

## Milestone 2: Scalar ALU

Deliverable: scalar-only eBPF programs work.

Support:

- `mov reg`
- `add/sub` immediate
- `add/sub` register
- simple conditional jump if needed by tests

Rules:

- scalar operations keep destination registers scalar
- scalar operations on capability registers are rejected unless explicitly
  implemented as capability offset derivation

Definition of done: scalar tests produce the same result across interpreter,
stock JIT, and CHERI JIT.

## Milestone 3: Bounded Stack

Deliverable: stack accesses are capability-authorized.

Steps:

1. Create a bounded stack capability in the prologue.
2. Mark eBPF `R10` as `capability(stack)`.
3. Support stack-relative load/store for fixed offsets.
4. Use capability-authorized data load/store instructions.
5. Use `CLC`/`CSC` only for capability spills, not normal integer data.

Tests:

- in-bounds stack store/load succeeds
- out-of-bounds stack load traps
- out-of-bounds stack store traps

Definition of done: CHERI JIT traps the OOB stack tests, while the in-bounds
test succeeds.

## Milestone 4: Bounded Context

Deliverable: context accesses are capability-authorized.

Steps:

1. Pass a test context object to the CHERI JIT.
2. Derive a bounded context capability for eBPF `R1`.
3. Support fixed-offset context loads.
4. Reject or trap context access through scalar registers.

Tests:

- in-bounds context read succeeds
- out-of-bounds context read traps

Definition of done: the CHERI JIT traps OOB context access before reading past
the context object.

## Milestone 5: Helper Shim

Deliverable: one helper can return a bounded map-value-like capability.

Steps:

1. Define a tiny fake map value object in the test harness.
2. Implement one helper shim that returns:
   - null, or
   - a capability bounded to exactly one map value
3. Mark the return register as `capability(map_value)` when the helper succeeds.
4. Support fixed-offset loads/stores through that returned capability.

Tests:

- in-bounds map-value access succeeds
- access past `value_size` traps
- null helper return is handled without fabricating authority

Definition of done: helper-returned memory is bounded by the shim, not by the
ambient address space.

## Milestone 6: CVE-Pattern Tests

Deliverable: minimal programs demonstrate the two thesis CVE patterns.

`CVE-2023-2163` pattern:

- construct a pointer with attacker-controlled offset
- make baseline execution reach an OOB access
- require CHERI execution to trap because the derived capability remains bounded

`CVE-2021-4204` pattern:

- pass a bounded object through a helper-like interface
- omit or lie about the object size at the software-check layer
- require CHERI execution to trap at the true object bound

Definition of done: each test has three outcomes recorded:

- interpreter or stock JIT baseline behavior
- CHERI JIT in-bounds behavior
- CHERI JIT OOB trap behavior

## Milestone 7: Measurements

Deliverable: small, honest performance numbers.

Measure:

- JIT compile time
- execution time for scalar-only program
- execution time for stack/context/map in-bounds programs
- trap behavior for OOB programs

State clearly that QEMU numbers are useful for relative trends, not native
Morello performance claims.

## Stop Conditions

Use the hybrid fallback only if full capability-per-pointer semantics blocks the
MVP.

Fallback:

- narrow DDC around the whole eBPF sandbox
- keep object-level capability tests where possible
- report this as coarse sandboxing, not fine-grained verifier offload

## Final Thesis Claim

The strong claim is:

> For selected eBPF verifier-missed spatial safety patterns, a CHERI-aware uBPF
> JIT can preserve pointer bounds into native execution and turn illegal memory
> accesses into deterministic capability exceptions.

The claim is not:

> CHERI removes the need for the Linux eBPF verifier.
