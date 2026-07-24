# Helper-Returned Map Capability Milestone

This note records the first helper/map pointer-root test for the CHERI uBPF JIT.
It is a reduced analogue for CVE-2021-4204-style bugs where helper/map argument
validation mistakes can lead to out-of-bounds access through helper-returned
memory.

## What Was Added

The prototype now has an opt-in CHERI hook:

```c
ubpf_cheri_set_map_value_helper_index(vm, helper_index);
```

When the CHERI JIT sees a call to that configured helper index, it marks `r0` as
a `CHERI_REG_MAP_VALUE_CAP` instead of a scalar. Loads and scalar stores through
that register are then emitted as capability-relative memory operations, just as
context and stack accesses are.

This is intentionally narrow. The regular uBPF helper ABI returns `uint64_t`, so
it cannot honestly carry an arbitrary CHERI capability as a helper return. The
hook models a trusted helper returning a bounded map-value capability without
claiming full purecap helper ABI support.

## Reproduction

Hand-encoded helper/map suite:

```sh
make run-helper-map-cap-host
sg docker -c 'make run-cheri-helper-map-cap'
sg docker -c 'make helper-map-cap-comparison'
```

Compiler-generated helper/map path, using `clang -target bpf` and the uBPF ELF
loader:

```sh
make run-generated-bpf-host
sg docker -c 'make run-cheri-generated-bpf'
sg docker -c 'make generated-bpf-comparison'
```

`make cheri-check` also includes the CHERI generated-BPF suite and the
hand-encoded helper/map suite.

## Latest Result

Verified on 2026-07-24 with `sg docker -c 'make helper-map-cap-comparison'` and
`sg docker -c 'make run-cheri-generated-bpf'`.

| Case | Host x86_64 uBPF JIT | CHERI uBPF JIT | Result |
| --- | --- | --- | --- |
| `helper_map_read_in_bounds` | returned `0x2000` | returned `0x2000` | valid helper map read preserved |
| `helper_map_write_in_bounds` | returned `0x5a` | returned `0x5a` | valid helper map write/read preserved |
| `helper_map_read_oob` | returned `0xfeedfacecafebeef` | `SIGPROT` / `PROT_CHERI_BOUNDS` | unsafe baseline, hardware bounds trap under CHERI |
| `helper_map_write_oob` | returned `0x0` after executing write | `SIGPROT` / `PROT_CHERI_BOUNDS` | unsafe baseline, hardware bounds trap under CHERI |

The same four helper/map cases now also exist as compiler-generated BPF fixtures
in `workspace/bpf/helper_map_*.c`. The generated-BPF harness verifies that the
uBPF ELF loader resolves the helper call and that the CHERI JIT applies the same
helper-returned map-value capability semantics.

The CHERI trap output is symbolic, for example:

```text
trapped: signal=34 code=1(PROT_CHERI_BOUNDS) trapno=36 capreg=0
```

## CVE-2021-4204 Relevance

This is not a full Linux ring-buffer exploit port. It models the important final
shape for the thesis claim:

```text
helper returns pointer-like access to a bounded memory object
program derives an invalid offset
program performs read/write through that helper-returned root
```

On the non-capability host JIT, the invalid access executes. On the CHERI JIT,
the access reaches the machine instruction and the hardware raises a bounds
violation.

## Current Limits

- The helper-returned root is opt-in and trusted by helper index.
- The current hook models one map-value root by reusing the bounded context
  capability as the returned map value in the test harness.
- It does not implement full map metadata, map lookup semantics, ring-buffer
  helpers, or helper-specific argument validation.
- It does not make arbitrary uBPF helpers capability-returning; the scalar helper
  ABI still cannot carry CHERI capabilities generally.

The result is still useful because it moves the prototype beyond context/stack
only and demonstrates that helper-returned memory roots can be added to the JIT
provenance model in a controlled, fail-closed way.
