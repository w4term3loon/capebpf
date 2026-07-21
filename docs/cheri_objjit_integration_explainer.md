# CHERI Object-Backed JIT Integration Explainer

This note explains the development pivot from raw anonymous mmap JIT code to
object-backed Morello purecap JIT code. It is intended as reference material for
the final report.

## The Short Version

The project goal is still to make generated uBPF/eBPF JIT code benefit from
CHERI bounds enforcement.

The working path is now:

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
bytes into an executable buffer.


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

The current backend deliberately does not solve that yet. It tracks `R10` as a
stack-capability kind and rejects unsupported stack memory operations.

That is the right scope for now. The first object-backed JIT milestone should
stay focused on context loads through the original `R1` capability:

```text
R1 context capability loads only
no stack memory
no stores
no atomics
no helper-returned pointers
```

Then stack support can be added as a separate milestone.

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

Under CheriBSD purecap, the integrated `ubpf_compile()` path now:

1. Checks whether the loaded program is either `LDXDW r0, [r1+offset]; EXIT`
   or a single `MOV64_REG rN, r1` alias followed by that load and `EXIT`.
2. Requires the source register to be the original `R1` context capability or
   that one direct alias.
3. Requires the load offset to be non-negative and 8-byte aligned.
4. Loads the matching object-backed artifact, currently
   `/mnt/cheri_objjit_offset_<offset>.so` by default.
5. Resolves `bpf_entry` with `dlsym`.
6. Stores the `dlopen` handle on the VM so `ubpf_destroy()` can `dlclose()` it.
7. Returns the loader-created `bpf_entry` function capability as the JIT entry.

Unsupported programs still fail closed through the CHERI translator policy. The
integrated test verifies that stack stores/loads and a clobbered-`R1` context
load are rejected at compile time.

## Observed Integrated Result

`sg docker -c 'make run-cheri-objjit-compile'` currently passes. The observed
important behavior is:

```text
context_load_8:
    ubpf_compile returns a sealed sentry function capability
    fn(ctx, sizeof(ctx)) returns 0xfeedfacecafebeef

context_load_4096:
    ubpf_compile returns a sealed sentry function capability
    fn(ctx, sizeof(ctx)) traps with PROT_CHERI_BOUNDS

context_alias_load_8:
    r6 = r1; r0 = *(u64 *)(r6 + 8); exit returns 0xfeedfacecafebeef

context_alias_load_4096:
    r6 = r1; r0 = *(u64 *)(r6 + 4096); exit traps with PROT_CHERI_BOUNDS

stack_store_load:
    ubpf_compile rejects unsupported memory opcode 0x7b

clobbered_r1_load:
    ubpf_compile rejects because R1 is no longer the context capability
```

That is the current strongest result for the thesis direction: a uBPF-loaded
program reaches a JIT-compiled entry point where generated object-backed Morello
code performs the memory operation directly, and CHERI enforces the context
object bounds.

## Remaining Blocking Factors

The main blocker is no longer proving that direct generated object-backed memory
operations can work. That is proven for the narrow context-load shape. The
remaining blockers are engineering scope and generality:

1. `ubpf_compile()` currently selects pre-generated offset-named shared objects.
   It does not yet emit, compile, and load a fresh per-program object by itself.
2. The admitted instruction subset is intentionally tiny: one final 64-bit
   context load and `exit`, optionally preceded by one direct `R1` alias.
3. Stack memory, stores, atomics, helper-returned pointers, and map-value
   accesses are still rejected.
4. The raw anonymous mmap JIT path still has the lower-level in-bounds
   `PROT_CHERI_TAG` failure. That blocker is now resolved by entering the mmap code through a capmode address (`addr | 1`); keep the repro as a regression test.
5. Object-backed code cannot be patched like the existing raw JIT buffer, so
   late external function registration currently fails closed for object-JIT
   code.

## Sensible Next Iteration

The next iteration should remove the prebuilt-artifact shortcut while keeping
the same narrow safety policy.

Goal:

```text
make `ubpf_compile()` generate and load the object-backed artifact for the
proven direct and single-alias context-load shapes instead of selecting a
prebuilt file
```

Concrete scope:

1. Keep `run-cheri-objjit-context-repro` as the reference proof.
2. Keep `run-cheri-objjit-compile` as the integrated acceptance test.
3. Move the object generation logic from the Makefile/Python prototype toward a
   callable compile step.
4. Generate a unique temporary Morello assembly/object/shared-object artifact
   for the loaded eBPF bytes.
5. Load that artifact with `dlopen`, resolve `bpf_entry`, and keep the current
   `dlclose` VM lifetime cleanup.
6. Preserve the fail-closed policy for unsupported memory behavior.

Non-goals for that iteration:

- no stack support;
- no stores;
- no atomics;
- no helper-returned pointer support;
- no attempt to fix raw anonymous mmap JIT memory;
- no broad eBPF instruction coverage.

That gives a clean milestone:

```text
prebuilt object-backed compile proof
  -> per-program object-backed compile proof
```
