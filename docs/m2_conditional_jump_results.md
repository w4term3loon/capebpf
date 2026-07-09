# CHERI JIT Conditional Jumps — Primary Research Data

**Test platform**: CheriBSD purecap on QEMU Morello / x86_64 host

**Test source**: `workspace/test_m2_jmp.c`

**Test date**: July 2026 session

## Method

Six eBPF programs testing conditional jump opcodes: `JEQ_IMM`,
`JGT_IMM`, `JNE_IMM`, `JEQ_REG`, and a backward-branch loop. Each
program is run through both the interpreter and the CHERI JIT.

## Results

```
test1: JEQ_IMM taken (r0==0 -> +2)
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test2: JEQ_IMM not taken (r0==1)
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test3: JGT_IMM (r0=5 > 3 -> +2)
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test4: JNE_IMM (r0=7 != 0 -> +1)
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test5: JEQ_REG taken (r1==r2 -> +1)
  interp: r0=42 (expect 42) OK
  cheri_jit: r0=42 (expect 42) OK
test6: loop (3 iterations, r0 should be 3)
  interp: r0=3 (expect 3) OK
  cheri_jit: r0=3 (expect 3) OK
```

## Summary

| Feature | Interpreter | CHERI JIT |
|---------|-------------|-----------|
| JEQ_IMM (taken) | ✅ | ✅ |
| JEQ_IMM (not taken) | ✅ | ✅ |
| JGT_IMM | ✅ | ✅ |
| JNE_IMM | ✅ | ✅ |
| JEQ_REG | ✅ | ✅ |
| Backward loop (3 iterations) | ✅ | ✅ |

**Conclusion**: Conditional jumps extend the scalar-only CHERI JIT to
support branch-based control flow. Both forward jumps and backward
jumps (loops) work correctly on both the interpreter and CHERI JIT.
Combined with M2 (ALU), the CHERI JIT can now run any eBPF program
that uses only `mov`, `add`, `sub`, conditional jumps, and `exit` —
without any memory load/store (still blocked by M3 W^X).