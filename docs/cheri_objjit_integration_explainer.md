# CHERI Object-Backed JIT Integration Explainer

This note explains the development pivot from raw anonymous mmap JIT code to
object-backed Morello purecap JIT code. It is intended as reference material for
the final report.

Status update, 2026-07-22: this is now historical/fallback context, not the
primary implementation route. The raw anonymous mmap path was later fixed by
entering generated Morello code in C64 mode (`addr | 1`), and the current uBPF
integration uses that direct mmap path by default. The object-backed route remains
useful as independent reference evidence that loader-created purecap code can
perform the same bounded memory operations.

## The Short Version

The project goal is still to make generated uBPF/eBPF JIT code benefit from
CHERI bounds enforcement.

The object-backed fallback path described here is:

```text
raw eBPF bytes
  -> parsed by object-JIT emitter
  -> generated Morello assembly
  -> compiled into a purecap shared object
  -> loaded by CheriBSD runtime loader
  -> called as a CHERI function capability
```

The important point is that the generated loaded code performs the memory load
directly. There is no helper function doing the memory access for it.

## What Failed First

The first direct-JIT approach emitted compiler-verified Morello instruction bytes
into anonymous executable memory:

```asm
ldr x0, [c0, #8]
ret c30
```

This was expected to load `ctx[1]` from the context capability in `c0`.

The generated anonymous code could execute simple instructions:

```text
mov w0, #42
ret c30
```

It could also inspect the incoming context capability:

```asm
gctag x8, c0
gclen x0, c0
```

Those probes showed that `c0` arrived tagged and with the expected bounds.
However, the actual in-bounds memory load still trapped:

```text
SIGPROT
si_code=PROT_CHERI_TAG
```

This happened even when the mapping used `PROT_CAP`, `PROT_MAX`, sentries,
`mprotect`, and CheriBSD process controls such as `PROC_PROTMAX` and W+X
permission.

## What That Means

The instruction encoding was not the main problem. The bytes for:

```asm
ldr x0, [c0, #8]
ret c30
```

were verified against compiler output.

The more likely problem is how the generated code was introduced into the
process. Anonymous mmap memory can hold executable bytes, and it can execute
simple instructions, but it does not appear to receive the same purecap/C64
code metadata and function-capability treatment as code loaded by the CheriBSD
runtime loader.

In other words:

```text
correct instruction bytes are necessary
but not sufficient
```

The code also has to live in memory in a way that CheriBSD/Morello treats as
proper purecap executable code.

## What A Shared Object Is

A shared object is a dynamically loadable binary module, normally a `.so` file.
It is similar to a shared library.

In this project, the generated shared object contains a generated function:

```asm
bpf_entry:
    ldr x0, [c0, #offset]
    ret c30
```

The test process loads the shared object with:

```c
void *handle = dlopen("/mnt/cheri_objjit_in_bounds.so", RTLD_NOW | RTLD_LOCAL);
```

Then it looks up the generated function:

```c
bpf_entry_fn fn = (bpf_entry_fn)dlsym(handle, "bpf_entry");
```

On CheriBSD purecap, that `dlsym` result is not just an integer address. It is a
CHERI function capability, specifically a sealed sentry capability, that can be
called.

So `dlopen`/`dlsym` gives the process a loader-created function capability for
the generated code.

## Why Loading Helps

The CheriBSD runtime loader knows how to map purecap code correctly. It maps the
object's code, applies relocations, sets up capability metadata, and returns
callable function capabilities for symbols.

That is the part raw anonymous mmap did not successfully reproduce.

The key difference is:

```text
raw mmap path:
    bytes copied into anonymous executable memory
    manually create sentry
    in-bounds CHERI load still traps with PROT_CHERI_TAG

object-backed path:
    generated code compiled/linked as purecap object
    runtime loader maps it
    dlsym returns function capability
    in-bounds CHERI load succeeds
    OOB CHERI load traps with PROT_CHERI_BOUNDS
```

## Working Memory Example

The test passes a small bounded context object:

```c
uint64_t ctx[] = {
    0x1111111111111111,
    0xfeedfacecafebeef
};
```

In purecap C, `ctx` is a capability, not just an address. It has:

- a valid tag;
- a base address;
- a length of `0x10`;
- permissions;
- a current address.

The generated function receives that context capability in `c0`.

For the in-bounds case, the generated code is:

```asm
bpf_entry:
    ldr x0, [c0, #8]
    ret c30
```

Offset `8` is inside the 16-byte context object, so this returns:

```text
0xfeedfacecafebeef
```

For the out-of-bounds case, the generated code is:

```asm
bpf_entry:
    ldr x0, [c0, #4096]
    ret c30
```

Offset `4096` is outside the context capability bounds, so CHERI raises:

```text
SIGPROT
PROT_CHERI_BOUNDS
```

This is the desired security property.

## Why This Is Still JIT Work

This route does not use a helper to perform the memory operation.

The helper-mediated fallback looked like this:

```text
JIT code
  -> call compiled helper
  -> helper performs memory load
```

That proves CHERI can enforce bounds, but it weakens the claim that the JIT
itself benefits from CHERI.

The object-backed route looks like this:

```text
eBPF bytecode
  -> generated Morello code
  -> generated code performs memory load directly
```

That is much closer to the thesis claim.

## Why Not Just Emit The Working Memory Operation From The Existing JIT?

The existing raw JIT already can emit the memory instruction:

```asm
ldr x0, [c0, #8]
```

The blocker is not that we do not know how to encode the instruction. The
blocker is that code placed into anonymous mmap memory does not currently behave
like loader-created purecap code for direct memory operations.

So a Morello-specific backend is still the right direction, but it likely needs
to be object-backed rather than raw-mmap-backed:

```text
Morello object-backed backend:
    parse admitted eBPF program
    emit Morello assembly/object code
    compile/link/load as purecap code
    return loaded bpf_entry function capability
```

That is different from a traditional JIT backend that only writes instruction
bytes into an executable buffer. The current primary backend has since returned
to anonymous mmap-generated code after fixing C64 entry, but the object-backed
route remains a useful fallback and diagnostic comparison.


## What "Anonymous JIT Memory" Means

In this context, "anonymous" is a memory-mapping term. It does not mean the JIT
is unauthenticated or intentionally given broad authority.

A traditional JIT usually allocates executable memory like this:

```c
mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
```

That creates fresh process memory not backed by a file, object, or shared
library. The usual JIT flow is:

```text
allocate anonymous memory
write machine-code bytes into it
mark it executable
call it
```

This is common because it is fast and simple.

For this project, the problem is not that anonymous JIT memory is too powerful.
The problem is almost the opposite: on CheriBSD/Morello, anonymous executable
memory does not appear to receive all of the purecap code-state treatment that
loader-created code receives. It can execute simple instructions, but direct
CHERI memory loads from that code still fail in bounds.

The object-backed path gives the runtime loader an ELF/shared-object artifact.
The loader then maps the code and returns a callable function capability for
`bpf_entry`.

## Restricting The JIT

Using object-backed code does not mean giving the JIT permission to do arbitrary
operations.

The intended security model is still fail-closed:

```text
eBPF bytecode
  -> validate a narrow supported subset
  -> reject unsupported memory behavior
  -> generate object-backed Morello code only for admitted programs
  -> load generated object
  -> call generated bpf_entry function capability
```

The object-backed route solves the code-loading/code-capability problem. It does
not replace validation. The JIT still needs a strict policy for which eBPF
programs it will compile.

## Which Operations Need To Be Object-Backed?

The current practical rule is:

```text
any generated code that performs CHERI-sensitive memory operations should be
object-backed
```

This includes:

- context loads such as `r0 = *(u64 *)(r1 + offset)`;
- future stack loads/stores if a CHERI-bounded eBPF stack is implemented;
- future loads through map values or helper-returned capabilities;
- stores, if the backend ever admits them;
- atomics, if the backend ever admits them.

Scalar operations are not the reason anonymous mmap fails. These worked in the
raw JIT experiments:

- integer arithmetic;
- register moves;
- comparisons;
- branches;
- scalar returns;
- capability-inspection probes such as `gctag` and `gclen`.

However, mixing two execution strategies inside one eBPF program would add a lot
of complexity:

```text
raw mmap code for scalar operations
object-backed code for memory operations
transitions between both
```

That is not the right next step. The cleaner research backend is:

```text
for CHERI JIT mode:
    generate the whole admitted program as object-backed purecap code
```

Even if a program contains mostly scalar instructions, keeping the whole admitted
program object-backed avoids switching execution models mid-program.

## What About The eBPF Stack?

The eBPF stack is a separate problem from code loading.

In eBPF, register `R10` represents the frame pointer for stack access. A safe
CHERI implementation needs to decide:

- what object backs the eBPF stack;
- what bounds its stack capability has;
- which register carries that capability;
- how capability state is tracked through moves and scalar clobbers;
- which stack loads/stores are admitted.

The backend now solves the first stack slice for the direct mmap route. It
derives `R10` as a bounded stack capability, clears that bounded stack in the
prologue, preserves stack capability provenance through `MOV64_REG` and 64-bit
immediate `ADD/SUB`, and admits scalar stack loads/stores through tracked stack
capabilities. Stack OOB accesses trap with `PROT_CHERI_BOUNDS`; uninitialized
scalar stack reads return zero.

The remaining stack-related work is no longer basic load/store enablement. It is
control-flow-sensitive provenance, additional memory widths, capability spills,
and integration with helper/map-returned pointer roots.

## Current Integrated Prototype

The current prototype supports these exact eBPF shapes:

```text
r0 = *(u64 *)(r1 + offset)
exit

rN = r1
r0 = *(u64 *)(rN + offset)
exit
```

The standalone generator still parses raw eBPF bytes, for example:

```text
79 10 08 00 00 00 00 00
95 00 00 00 00 00 00 00
```

That means:

```text
LDXDW r0, [r1 + 8]
EXIT
```

It emits object-backed Morello code like:

```asm
bpf_entry:
    ldr x0, [c0, #8]
    ret c30
```

There are now two useful targets:

```sh
sg docker -c 'make run-cheri-objjit-context-repro'
sg docker -c 'make run-cheri-objjit-compile'
```

The first target is the standalone reference proof. The second target goes
through the uBPF-facing API:

```text
ubpf_load(...)
ubpf_compile(...)
fn(ctx, ctx_len)
```

This section records the object-backed detour. It is now superseded by the
direct anonymous mmap JIT path entered in Morello C64 mode. The object-backed
route is retained as fallback/reference evidence and can still be selected with
`UBPF_CHERI_USE_OBJJIT=1`, but it is not the primary implementation route.

Under CheriBSD purecap, the current default `ubpf_compile()` path now:

1. Emits anonymous mmap direct-JIT code and enters it through a capmode address
   (`addr | 1`) so generated code runs in Morello C64 state.
2. Tracks context and stack capability roots: `R1` starts as the context
   capability, and `R10` starts as a bounded eBPF stack capability.
3. Preserves capability provenance across `MOV64_REG` and 64-bit immediate
   `ADD/SUB` for tracked context/stack capabilities.
4. Allows scalar loads through tracked context capabilities and scalar
   loads/stores through tracked stack capabilities.
5. Clears the bounded eBPF stack in the prologue, so uninitialized scalar stack
   reads return zero rather than prior native stack contents.
6. Applies conservative branch-join provenance: a register keeps capability kind
   only if all reaching paths preserve the same kind.
7. Rejects context stores, capability stores, atomics, local calls,
   helper/map-returned pointers, and loads from untracked scalar pointers.

## Observed Integrated Result

`sg docker -c 'make run-cheri-objjit-compile'` currently passes. Despite the
historical target name, this exercises the default direct mmap CHERI JIT unless
`UBPF_CHERI_USE_OBJJIT=1` is set. The important behavior is:

```text
context_load_8:
    ubpf_compile returns a sealed sentry function capability
    fn(ctx, sizeof(ctx)) returns 0xfeedfacecafebeef

context_load_4096:
    fn(ctx, sizeof(ctx)) traps with PROT_CHERI_BOUNDS

context_alias_load_8 / context_ptr_add_load_8 / branch_preserves_context:
    tracked aliases, immediate pointer arithmetic, and branch paths that preserve
    the context capability return 0xfeedfacecafebeef

context_alias_load_4096 / context_ptr_add_load_4096:
    tracked aliases and immediate pointer arithmetic trap with PROT_CHERI_BOUNDS

stack_store_load / immediate_stack_store_load / stack_ptr_add_store_load:
    in-bounds stack scalar stores and loads return 42

uninit_stack_ptr_add_load:
    returns 0 from the zeroed bounded eBPF stack

stack_store_oob / stack_load_oob / stack_ptr_add_load_oob:
    trap with PROT_CHERI_BOUNDS

context_store / capability_stack_store / clobbered_r1_load / branch_join_clobbered_context:
    rejected at compile time
```

That is the current strongest result for the thesis direction: a uBPF-loaded
program reaches a JIT-compiled entry point where generated direct mmap Morello
code performs supported memory operations itself, and CHERI enforces context
and stack bounds for those operations.

## Remaining Blocking Factors

The main blocker is no longer code loading or basic stack memory. The remaining
blockers are provenance generality and broader eBPF coverage:

1. Branch joins are modeled conservatively, not path-sensitively; programs that
   require proving a scalar branch infeasible may still reject.
2. Memory-width coverage should be expanded and tested for `B`, `H`, `W`, `DW`,
   and signed loads.
3. Helper-returned pointers and map values need explicit bounded capability
   roots before helper/map memory can be admitted.
4. Atomics, capability spills, context stores, and local calls remain rejected.
5. The object-backed route is no longer required for the main path, but remains
   useful as a reference for loader-created purecap code.

## Sensible Next Iteration

The next iteration should broaden supported memory shapes while preserving
fail-closed provenance.

Goal:

```text
expand memory widths for the already-supported context and stack roots, then
introduce helper/map pointer roots with explicit bounds
```

Concrete scope:

1. Keep `run-cheri-objjit-context-repro` as the object-backed reference proof.
2. Keep `run-cheri-objjit-compile` as the direct mmap integrated acceptance
   test.
3. Keep branch-join regression tests as new pointer roots are introduced.
4. Add byte/half/word/doubleword stack and context memory tests.
5. Keep helper/map pointers, atomics, capability stores, context stores, and
   local calls rejected until their provenance rules are explicit.

That gives a clean milestone:

```text
context/stack direct-JIT proof
  -> branch-safe provenance proof
  -> broader memory-width and helper/map-root proof
```
