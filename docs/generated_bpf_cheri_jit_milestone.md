# Generated BPF to CHERI JIT Milestone

This note records the point where the project moved from handwritten eBPF byte
arrays to a reproducible compiler-generated eBPF path.

The milestone is:

```text
C source
  -> clang -target bpf
  -> ELF eBPF object
  -> uBPF ELF loader
  -> CHERI-aware uBPF JIT
  -> Morello/CheriBSD execution
```

The current permanent test is:

```text
workspace/bpf/stack_array.c
  -> workspace/bpf/stack_array.o
  -> workspace/test_cheri_generated_bpf
```

It is run with:

```sh
make run-cheri-generated-bpf
```

It is also part of:

```sh
sg docker -c 'make cheri-check'
```

## Why There Is A Fixture

The fixture is not a workaround for incompatible bytecode.

eBPF bytecode is the portable layer. A valid eBPF program can be loaded by uBPF
on x86 or by the CHERI-aware uBPF path on Morello. The non-portable part is the
machine code produced by the JIT backend:

```text
same eBPF bytecode
  -> x86 JIT emits x86-64 machine code
  -> CHERI JIT emits Morello capability-aware machine code
```

The reason for keeping a fixture is test control. We need a small C program that
forces clang to emit the specific stack-indexing pattern that used to be
unsupported by the CHERI backend. Without `volatile`, clang optimizes the local
stack array away and produces a valid eBPF program that does not test stack
memory at all.

The fixture therefore uses:

```c
volatile unsigned char slots[40];
unsigned int index = (unsigned int)(ctx->a & 7);

slots[index] = 0x5a;
return slots[index] + (int)((ctx->b - ctx->a) >> 8);
```

This is intentionally small and header-free so it can be compiled by ordinary
host clang without Linux kernel headers.

## What Clang Emits

The host command:

```sh
clang -target bpf -O2 -g0 -c workspace/bpf/stack_array.c -o workspace/bpf/stack_array.o
```

produces an ELF eBPF object. The important generated instructions are:

```text
r2 = *(u64 *)(r1 + 0x0)
r3 = r2
r3 &= 0x7
r4 = r10
r4 += -0x28
r4 += r3
r3 = 0x5a
*(u8 *)(r4 + 0x0) = r3
r3 = *(u8 *)(r4 + 0x0)
r0 = *(u64 *)(r1 + 0x8)
r0 -= r2
r0 >>= 0x8
r0 += r3
exit
```

The critical pattern is:

```text
r4 = r10
r4 += -0x28
r4 += r3
*(u8 *)(r4 + 0x0) = r3
r3 = *(u8 *)(r4 + 0x0)
```

`r10` is the eBPF frame pointer. On a non-capability architecture this can be
treated as integer address arithmetic. On CHERI it must remain a bounded stack
capability. The generated code is valid eBPF, but the CHERI JIT has to translate
it in a way that preserves capability provenance.

## What The CHERI JIT Needed

Earlier, the CHERI JIT could handle immediate stack offsets such as:

```text
r5 = r10
r5 += -8
*(u64 *)(r5 + 0) = r0
```

Compiler-generated stack arrays also use a scalar register as part of the
offset:

```text
r4 = r10
r4 += -40
r4 += r3
```

The backend therefore needed support for:

```text
tracked stack capability + scalar register offset
```

The implemented rule is conservative:

- if the destination register is a tracked capability;
- and the operation is `ADD64_REG` or `SUB64_REG`;
- and the source register is a scalar;
- then emit Morello capability-relative arithmetic that keeps the destination as
  a capability.

Unsupported capability arithmetic is still rejected instead of silently
scalarizing or fabricating provenance.

Conceptually, the generated Morello operation is:

```asm
add Cd, Cn, Xm, uxtx
```

That means:

```text
new capability = old capability + scalar byte offset
```

The provenance and bounds come from the input capability. The scalar register is
only an offset. That is the key CHERI property: the JIT can allow dynamic stack
indexing without turning stack capabilities into raw integers.

For `SUB64_REG`, the JIT first negates the scalar offset into a temporary scalar
register and then uses the same capability-add path.

## ELF Loading Path

The normal purecap uBPF build in this repository does not expose the ELF loader
API because `UBPF_HAS_ELF_H` is disabled in the checked-in uBPF config.

The generated-BPF target builds a separate temporary uBPF library with:

```text
-DUBPF_HAS_ELF_H
```

This enables:

```c
ubpf_load_elf_ex(vm, elf, elf_len, "foo", &errmsg)
```

The test harness then calls:

```c
ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
uint64_t result = fn(ctx, sizeof(ctx));
```

The context is:

```c
uint64_t ctx[] = {0x1000ULL, 0x2000ULL};
```

The expected result is:

```text
0x5a + ((0x2000 - 0x1000) >> 8) = 0x5a + 0x10 = 0x6a
```

## Verified Result

The permanent test prints:

```text
generated BPF CHERI JIT test
  object:   /mnt/bpf/stack_array.o
  symbol:   foo
  returned: 0x6a
  expected: 0x6a
```

The VM command exits with:

```text
__CHERI_VM_RC:0__
```

The broader CHERI check also passes:

```sh
sg docker -c 'make cheri-check'
```

That check now includes both:

- the CHERI translator accept/reject suite;
- the generated C-to-BPF-to-CHERI-JIT test.

## What This Proves

This proves that the project no longer depends only on handwritten eBPF byte
arrays for the supported stack-memory path.

It demonstrates that:

- ordinary host clang can generate the eBPF object;
- uBPF can load that ELF object;
- the CHERI JIT can compile the generated bytecode;
- Morello executes the resulting code correctly;
- dynamic stack indexing can preserve CHERI capability provenance.

This is an important thesis milestone because it connects the prototype to the
normal eBPF development workflow: write C, compile to eBPF, then let the runtime
load and JIT it.

## What This Does Not Prove Yet

This is still a focused milestone, not a full verifier replacement.

Current limitations:

- the fixture uses only context loads and stack memory;
- helper calls, maps, packet pointers, and helper-returned pointer types are not
  covered by this generated-BPF test;
- the CHERI JIT supports a conservative subset of eBPF memory behavior;
- uninitialized stack semantics still require explicit policy or verifier state,
  even though stack zeroing prevents disclosure in the current exploit harness.

The next useful generated-BPF tests should add one feature at a time:

1. conditional branches around stack accesses;
2. multiple stack slots and wider load/store sizes;
3. context-derived offsets that reach CHERI bounds traps;
4. helper/map-style pointer roots once the prototype has a capability ABI for
   those objects.

## Current CVE-Style Harness Status

The current exploit harness still reports:

```text
JIT exploits that succeeded or crashed (baseline fails): 3/3
CHERI JIT missed: 0/3
```

The three covered categories are:

- out-of-bounds context read: CHERI JIT traps with `SIGPROT`;
- pointer leakage via `R0`: CHERI JIT blocks the program through register-kind
  policy;
- uninitialized stack read: CHERI JIT returns zero due to bounded stack zeroing,
  preventing disclosure.

These are CVE-shaped verifier-bypass categories, not exact reproductions of
full Linux kernel CVEs. They are useful because they isolate the final unsafe
memory or pointer behavior that CHERI is meant to constrain.
