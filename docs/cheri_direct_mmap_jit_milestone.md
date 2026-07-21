# CHERI Direct mmap JIT Milestone - 2026-07-21

This note summarizes the pivot from helper/object-mediated execution back to a true anonymous `mmap` JIT path.

## What Changed

The direct mmap JIT originally looked blocked because generated code could execute scalar instructions and inspect `c0`, but in-bounds loads like `ldr x0, [c0, #8]` trapped with `PROT_CHERI_TAG`.

The root cause was entry mode, not the mapping. Morello purecap code must be entered in C64 mode. CheriBSD derives this from bit 0 of the target address: an odd function capability address sets `PSR_C64`, then the kernel clears the bit before writing ELR. Loader-created purecap function capabilities already have this odd address. Our anonymous mmap JIT entry did not.

The fix is:

```c
void *entry = (void *)((uintptr_t)code | 1U);
entry = cheri_sentry_create(entry);
```

After this, anonymous mmap-generated code gets the same useful behavior as normal purecap code for the tested context loads.

## Evidence Now Proven

Passing targets:

```sh
sg docker -c 'make run-cheri-direct-jit-repro'
sg docker -c 'make run-cheri-objjit-compile'
sg docker -c 'make run-exploit-tests'
```

The compile-level uBPF test now proves:

- `LDXDW r0, [r1 + 8]; EXIT` returns `0xfeedfacecafebeef` through direct mmap JIT code.
- `LDXDW r0, [r1 + 4096]; EXIT` traps with `PROT_CHERI_BOUNDS`.
- `MOV64_REG r6, r1; LDXDW r0, [r6 + 8]; EXIT` preserves the context capability tag and returns the expected value.
- The same alias shape with offset `4096` traps with `PROT_CHERI_BOUNDS`.
- Stack stores/loads and other unsupported memory operations are rejected during translation for now.
- Clobbering `r1` before a context load is rejected, preserving the current context-capability contract.

## Why This Matters For The Thesis Claim

This is the first non-helper, non-loader-backed path where the uBPF compile API produces anonymous mmap JIT code and CHERI enforces an object-bounds differential on an eBPF-derived memory operation.

That supports a narrower but credible claim:

> A CHERI-aware uBPF JIT can carry an admitted eBPF pointer as a hardware capability and rely on CHERI bounds to catch spatial out-of-bounds context loads, while rejecting unsupported memory operations until their capability provenance rules are implemented.

It does not yet prove a complete verifier replacement.

## Current Boundary

The CHERI backend is intentionally restricted:

- `r1` starts as the context capability.
- simple `MOV64_REG` aliases of `r1` preserve capability provenance using `mov Cd, Cn`;
- loads are allowed only through the context capability or a tracked alias;
- memory stores, stack memory, atomics, and arbitrary pointer arithmetic remain fail-closed.

The object/shared-object JIT route remains as historical fallback and can still be selected with:

```sh
UBPF_CHERI_USE_OBJJIT=1
```

## Prologue/Epilogue Integration

The direct mmap backend now has the first proper purecap ABI frame setup:

- allocates one capability stack frame for C29/C30 save space plus the eBPF stack;
- saves/restores C29 and C30 with Morello capability-pair stores/loads;
- derives `r10`/`c10` as a bounded eBPF stack capability using `scbnds` with a register length, because the immediate form cannot represent the full uBPF stack size;
- rejects local eBPF function calls for now instead of emitting the stock arm64 scalar stack-spill sequence.

Current register allocation still avoids callee-saved registers for BPF state, so no additional callee-saved capability spills are required yet. If the backend later uses C19-C28, those must be saved/restored as capabilities, not scalar `x` registers.

Passing targets after this integration:

```sh
sg docker -c 'make run-cheri-direct-jit-repro'
sg docker -c 'make run-cheri-objjit-compile'
sg docker -c 'make run-exploit-tests'
sg docker -c 'make cheri-check'
```

## Next Engineering Step

The next sensible step is to prove stack memory one instruction class at a time:

- add a focused stack-store/load test that expects in-bounds stack access to succeed and out-of-bounds stack access to trap;
- lower stack loads/stores through the bounded `r10` capability only;
- keep atomics, helper-returned pointers, maps, and local calls rejected until their capability-provenance rules are explicit.
