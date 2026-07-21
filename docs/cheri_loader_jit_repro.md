# Loader-Backed Direct CHERI Code Repro - 2026-07-20

This note captures the first passing non-helper route around the anonymous mmap
code-load blocker. The repro is split across:

- `workspace/cheri_loader_jit_payload.c`
- `workspace/test_cheri_loader_jit_repro.c`

Run it with:

```sh
sg docker -c 'make run-cheri-loader-jit-repro'
```

## What It Tests

The target builds a purecap shared object with two exported functions:

```c
uint64_t loader_jit_load_u64(uint64_t *p) { return p[1]; }
uint64_t loader_jit_load_u64_oob(uint64_t *p) { return *(uint64_t *)((char *)p + 4096); }
```

The test binary loads that shared object with `dlopen`, resolves the function
capability with `dlsym`, and calls it with a 16-byte bounded stack object. The
loaded code performs the memory operation directly. There is no helper-mediated
load in this repro.

## Observed Result

The loader-backed direct-code path passes:

```text
[loader-backed direct code loader_jit_load_u64]
  mem arg                tag=1 sealed=0 sentry=0 ... len=0x10
  loaded fn              tag=1 sealed=1 sentry=1 ... perms=0x2c177
  returned              0xfeedfacecafebeef
  parent: child exit=0

[loader-backed direct code loader_jit_load_u64_oob]
  mem arg                tag=1 sealed=0 sentry=0 ... len=0x10
  loaded fn              tag=1 sealed=1 sentry=1 ... perms=0x2c177
  SIGPROT detail       signo=34 si_code=1(PROT_CHERI_BOUNDS) si_trapno=36 si_capreg=0
  parent: child exit=0

OK loader-backed direct code produced an in-bounds/OOB CHERI differential
```

## Interpretation

This is a materially better JIT-only route than the helper-mediated fallback.
It shows that code mapped by the CheriBSD runtime loader can execute a direct
capability memory load, return the in-bounds value, and fault out-of-bounds with
`PROT_CHERI_BOUNDS`. That is exactly the spatial differential the anonymous mmap
JIT path failed to produce.

This does not yet make uBPF's current raw mmap JIT work. It does show a credible
next architecture: emit Morello purecap code into an object/shared-object form,
let the loader create the executable capability state, then call the resulting
function capability as the JIT entry point.

## Superseded By Generated Object Proof

This hand-written shared-object repro is still useful as a loader sanity check,
but the stronger current evidence is `docs/cheri_objjit_context_repro.md`: that
target generates Morello assembly for the context-load shape and gets the same
in-bounds success / OOB `PROT_CHERI_BOUNDS` differential.

## Next Steps

1. Treat `docs/cheri_objjit_context_repro.md` as the active implementation path.
2. Integrate the generated-object backend behind a CHERI-specific JIT mode while
   keeping the raw mmap backend as a C64-entry regression diagnostic.
3. Keep the helper-mediated path as fallback only.
