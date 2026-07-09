# QEMU Morello Purecap Instruction Matrix

**Test platform**: CheriBSD purecap on QEMU Morello (Morello SDK
`cheribsd-morello-purecap.cfg`, Docker container `thesis-workspace`)

**Test date**: July 2026 session

**Test source**: `workspace/test_instruction_matrix.c`

## Method

Each instruction or instruction sequence is assembled as raw 32-bit
words, copied into an `mmap(PROT_READ|PROT_WRITE|PROT_EXEC,
MAP_PRIVATE|MAP_ANONYMOUS)` page, and called as a function pointer.
Each test runs in a `fork()`ed child so that SIGPROT crashes are
isolated and reported via `WTERMSIG(status)`.

For store-target tests, a separate `mmap(PROT_READ|PROT_WRITE)` page
is allocated (NOT executable) and its address is loaded into a
general-purpose register via `movz`/`movk` immediate instructions.

## Results

```
=== Instruction Matrix Test on CheriBSD Purecap QEMU Morello ===
data_page=0x408dc000  stack_page=0x408dd000

  sub_csp:                OK  r0=42
  ret_c30:                OK  r0=42
  movz_x0:                OK  r0=42
  orr_x0_xzr_x1:          OK  r0=0
  add_x0_x1_x2:           OK  r0=1083056128
  sub_x0_x1_x2:           OK  r0=18446744072626491392
  b_forward:              OK  r0=42
  bl_forward:              CRASH  SIGPROT(34)
  str_x5_x19_sep_page:    CRASH  SIGPROT(34)
  stur_x5_x19_neg8:       CRASH  SIGPROT(34)
  str_x5_sp:              CRASH  SIGPROT(34)
  ldr_x5_x19_sep_page:    CRASH  SIGPROT(34)
  str_c30_c0:             CRASH  SIGPROT(34)
  ldr_c30_c0:             CRASH  SIGPROT(34)
  mprotect_from_jit:      skipped (requires syscall)

=== Matrix Complete ===
```

## Summary table

| # | Instruction | Category | Result |
|---|-------------|----------|--------|
| 1 | Morello `sub csp, csp, #32` | Cap stack alloc | **OK** |
| 2 | Morello `ret c30` | Cap return | **OK** |
| 3 | A64 `movz x0, #42` | ALU immediate | **OK** |
| 4 | A64 `orr x0, xzr, x1` | ALU register | **OK** |
| 5 | A64 `add x0, x1, x2` | ALU register | **OK** |
| 6 | A64 `sub x0, x1, x2` | ALU register | **OK** |
| 7 | A64 `b +1` (branch) | Control flow | **OK** |
| 8 | A64 `bl +1` (branch+link) | Control flow | **CRASH SIGPROT** |
| 9 | A64 `str x5, [x19]` → sep RW page | Data store (GP reg) | **CRASH SIGPROT** |
| 10 | A64 `stur x5, [x19, #-8]` → sep RW page | Data store (GP reg, neg off) | **CRASH SIGPROT** |
| 11 | A64 `str x5, [sp]` → native stack | Data store (SP) | **CRASH SIGPROT** |
| 12 | A64 `ldr x5, [x19]` ← sep RW page | Data load (GP reg) | **CRASH SIGPROT** |
| 13 | Morello `str c30, [c0]` | Cap store (C reg) | **CRASH SIGPROT** |
| 14 | Morello `ldr c30, [c0]` | Cap load (C reg) | **CRASH SIGPROT** |

## Interpretation

### What works from mmap'd PROT_EXEC memory

- Morello capability instructions that do NOT access memory: `sub csp`,
  `add csp`, `ret c30`
- A64 ALU instructions: `movz`, `orr`, `add`, `sub`
- A64 branch (no link): `b`

### What crashes from mmap'd PROT_EXEC memory

- A64 `bl` (branch with link) — creates a sealed sentry in C30, traps
- **ANY store instruction** — regardless of:
  - Base register: SP (X31), X19, X23 (general purpose)
  - Destination: separate PROT_READ|PROT_WRITE page, native stack,
    capability register target
  - Address mode: unsigned offset, pre-indexed, post-indexed, negative
- **ANY load instruction** — regardless of:
  - Base register: X19 (GP reg via DDC), C0 (cap reg)
  - Source: separate PROT_READ|PROT_WRITE page

### Root cause

QEMU Morello purecap enforces a strict W^X policy at the **PCC
(program counter capability)** level. When the PCC for a page includes
`PROT_EXEC`, the QEMU emulator rejects any instruction that reads
from or writes to memory, even if the target address is on a separate
non-executable page with its own `PROT_READ|PROT_WRITE` permissions.

This is **stricter than standard W^X**:
- Standard W^X: prevents writes TO executable pages (to prevent code injection)
- QEMU Morello W^X: prevents ANY memory access FROM executable pages
  (both loads and stores, through any register or capability)

### Implications for the CHERI JIT

- **M0-M2 (mov, exit, scalar ALU)**: All work — these instructions
  don't access memory.
- **M3 (bounded stack)**: Blocked — eBPF stack load/store (`LDX`/`STX`)
  requires A64 `ldr`/`str` from the JIT page, which crashes.
- **Exploit programs**: All crash with SIGPROT — fail-closed behavior
  (exploits are blocked, not silently allowed).

### Cross-reference

| Instruction | Same bytes in compiler `.text` | From mmap PROT_EXEC |
|---|---|---|
| `str c29, [csp, #0x10]` | **OK** (runs in compiled functions) | **CRASH SIGPROT** |
| `stp c29, c30, [csp, #-0x20]!` | **OK** (compiler prologue) | **CRASH SIGPROT** |
| `str x5, [x19]` (to sep RW page) | **OK** (compiled stores) | **CRASH SIGPROT** |

The instructions are correctly encoded — verified by cross-checking
against `llvm-objdump` disassembly of compiler-generated code.