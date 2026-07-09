# CHERI JIT Scalar ALU (M2) Results — Primary Research Data

**Test platform**: CheriBSD purecap on QEMU Morello / x86_64 host

**Test source**: `workspace/test_m2.c`

**Test date**: July 2026 session

## Method

Seven eBPF programs exercising scalar ALU opcodes (`mov64`,
`add64`, `sub64` in both immediate and register forms). Each program
is run through the uBPF interpreter and the CHERI JIT. Results
are compared for correctness (r0 must equal 42).

## Results

```
test1: mov64_imm r0=42
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test2: mov64_reg r1=42, r0=r1
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test3: add64_imm r0=10, r0+=32
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test4: sub64_imm r0=100, r0-=58
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test5: add64_reg r1=20, r2=22, r0=r1+r2
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test6: sub64_reg r1=100, r2=58, r0=r1-r2
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test7: compound add r0=5+10+20+7
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
```

## Summary

| Test | eBPF opcode | Interpreter | CHERI JIT | Match? |
|------|-------------|-------------|-----------|--------|
| 1 | `mov64 imm` | 42 ✅ | 42 ✅ | ✅ |
| 2 | `mov64 reg` | 42 ✅ | 42 ✅ | ✅ |
| 3 | `add64 imm` | 42 ✅ | 42 ✅ | ✅ |
| 4 | `sub64 imm` | 42 ✅ | 42 ✅ | ✅ |
| 5 | `add64 reg` | 42 ✅ | 42 ✅ | ✅ |
| 6 | `sub64 reg` | 42 ✅ | 42 ✅ | ✅ |
| 7 | compound add | 42 ✅ | 42 ✅ | ✅ |

**Conclusion**: All 7 M2 scalar ALU tests pass on both the interpreter
and the CHERI JIT. Results match exactly. No backend changes were
needed — the stock arm64 JIT already handles these opcodes and the
A64 ALU instructions work from mmap'd JIT memory on QEMU Morello.