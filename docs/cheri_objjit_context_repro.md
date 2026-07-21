# Object-Backed CHERI JIT Context-Load Repro - 2026-07-20

This is the current strongest JIT-only route. It parses raw eBPF bytecode and
generates Morello purecap assembly for the narrow admitted uBPF shapes:

```text
r0 = *(u64 *)(r1 + offset)
exit

rN = r1
r0 = *(u64 *)(rN + offset)
exit
```

Purecap ABI mapping for this proof:

- uBPF `R1` context capability is passed as `c0`.
- uBPF `R0` scalar return value is returned as `x0`.

Run it with:

```sh
sg docker -c 'make run-cheri-objjit-context-repro'
```

## Generated Code

The checked-in generator is `tools/cheri_objjit_emit.py`. The Makefile now calls
it with raw eBPF bytes, for example:

```sh
python3 tools/cheri_objjit_emit.py \
  --program-hex '79 10 08 00 00 00 00 00 95 00 00 00 00 00 00 00' \
  --output workspace/cheri_objjit_offset_8.S
```

That bytecode is parsed as `LDXDW r0, [r1+8]` followed by `EXIT`. The generator
also accepts one leading `MOV64_REG rN, r1` alias, matching the OOB exploit
harness shape `r6 = r1; r0 = *(u64 *)(r6 + 4096); exit`. In both cases the
generated assembly loads from the original context capability:

```asm
.text
.p2align 4
.globl bpf_entry
.type bpf_entry,@function
bpf_entry:
        ldr x0, [c0, #8]
        ret c30
.size bpf_entry, .-bpf_entry
```

The Makefile generates two assembly files from raw eBPF bytecode, compiles them
as purecap shared objects, and runs `workspace/test_cheri_objjit_context_repro.c`
in CheriBSD:

- `workspace/cheri_objjit_offset_8.S` -> `workspace/cheri_objjit_offset_8.so`
- `workspace/cheri_objjit_offset_4096.S` -> `workspace/cheri_objjit_offset_4096.so`

Generated files are ignored by git.

## Build-Time Verification

The Morello SDK marks the generated entry as a C64/purecap function capability.
The symbol value is odd and objdump decodes the intended instruction:

```text
0000000000010520 <bpf_entry>:
   10520: f9400400      ldr     x0, [c0, #0x8]
   10524: c2c253c0      ret     c30
```

The OOB variant similarly decodes as:

```text
0000000000010520 <bpf_entry>:
   10520: f9480000      ldr     x0, [c0, #0x1000]
   10524: c2c253c0      ret     c30
```

## Observed Result

The generated object-backed JIT path passes:

```text
[object-backed CHERI JIT context_load_8]
  ctx arg                tag=1 sealed=0 sentry=0 ... len=0x10
  generated entry        tag=1 sealed=1 sentry=1 ... perms=0x2c177
  returned              0xfeedfacecafebeef
  parent: child exit=0

[object-backed CHERI JIT context_load_4096]
  ctx arg                tag=1 sealed=0 sentry=0 ... len=0x10
  generated entry        tag=1 sealed=1 sentry=1 ... perms=0x2c177
  SIGPROT detail       signo=34 si_code=1(PROT_CHERI_BOUNDS) si_trapno=36 si_capreg=0
  parent: child exit=0

OK object-backed CHERI JIT context load produced an in-bounds/OOB differential
```

## Interpretation

This is not helper-mediated enforcement. The generated loaded code executes the
memory operation directly. The runtime loader creates the executable purecap
function capability that the raw anonymous mmap path is missing.

This moves the project from "loaded hand-written C can show the CHERI bounds
property" to "raw eBPF bytes can be parsed into generated object-backed JIT code
that shows the CHERI bounds property" for the first context-load shape.

## Relationship To The uBPF Compile Path

This standalone repro remains the reference proof for generated object-backed
code. The uBPF-facing integration is now covered by:

```sh
sg docker -c 'make run-cheri-objjit-compile'
```

That target uses `ubpf_load()` and `ubpf_compile()` for the same narrow bytecode
shapes. Under CheriBSD purecap, `ubpf_compile()` recognizes the admitted shape,
loads the matching object-backed artifact with `dlopen`, resolves `bpf_entry`
with `dlsym`, and returns that loader-created function capability as the JIT
entry point.

The current integration uses pre-generated offset-named objects. It does not yet
compile arbitrary temporary objects from inside `ubpf_compile()`.

## Next Steps

1. Replace the offset-named prebuilt objects with per-program object generation.
2. Preserve the fail-closed register-kind policy: only original `R1`, or a
   single direct alias of original `R1`, is admitted for context-capability
   loads.
3. Expand from final context loads to simple ALU/branch programs around a
   context load.
4. Keep the raw anonymous mmap repro as a passing C64-entry regression test; see `cheri_direct_mmap_jit_milestone.md` for the resolved blocker.
5. Keep the helper-mediated route as fallback only.
