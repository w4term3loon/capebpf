# CHERI JIT Baseline (r0=42;exit) — Primary Research Data

**Test platform**: CheriBSD purecap on QEMU Morello

**Test source**: `workspace/test42.c`

**Test date**: July 2026 session

## Method

The simplest meaningful eBPF program (`r0 = 42; exit`) is run
through both the uBPF interpreter and the CHERI JIT to verify
end-to-end operation of the CHERI-aware backend.

## Results

```
interp rc=0 r0=42
cheri_jit r0=42
cheri_jit exit: 0
```

## Analysis

- **Interpreter**: Returns 0 (success), r0=42. ✅
- **CHERI JIT**: Returns 42 via `jit(NULL, 0)`. Exit code 0. ✅

The CHERI JIT correctly:
1. Compiles `BPF_MOV64_IMM(r0, 42)` and `BPF_EXIT` to native code
2. Emits the Morello prologue (PC-relative literal load for stack
   base, `b` to entry point)
3. Emits the eBPF instructions (A64 `movz x5, #42`, `b` to epilogue)
4. Emits the epilogue (`orr x0, xzr, x5` for return value, `ret c30`)
5. Executes the mmap'd code and returns 42

This validates Milestone 0 (baseline) and Milestone 1 (backend
skeleton) of the thesis plan.