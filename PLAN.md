# Project Roadmap

**Current date:** 2026-06-05 (end of Phase 1 / start of Phase 2)

---

## Phase 1 — Architecture & Environment (May, weeks 18–22) (done)

- [x] Study eBPF CVEs (CVE-2023-2163, CVE-2021-4204)
- [x] Setup CHERI/Morello toolchain (Docker + QEMU)
- [x] Register and memory mapping plan
- [x] Basic dev workflow (`Makefile`)

## Phase 2 — JIT Implementation (June, weeks 23–26)

- [ ] **Integrate uBPF** — cross-compile uBPF for purecap CheriBSD, verify it runs
- [ ] **Port arm64 JIT to CHERI** — map eBPF R0–R10 to CHERI C0–C10
- [ ] Replace `LDR`/`STR` with `CLC`/`CSC` for all memory access
- [ ] Narrow PCC and DDC bounds in JIT prologue
- [ ] **CVE-based test cases** — eBPF programs that reproduce OOB patterns
- [ ] **Verification harness** — detect capability exceptions in test output

## Phase 3 — Evaluation & Benchmarking (July, weeks 27–30)

- [ ] Performance assessment (latency, throughput, JIT compile time)
- [ ] Compare: interpreter × stock arm64 JIT × CHERI JIT
- [ ] Hybrid fallback (DDC-based coarse sandboxing)
- [ ] Fine-tuning JIT emission

## Phase 4 — Security Analysis (August, weeks 31–35)

- [ ] Replicate range analysis CVEs and verify hardware traps
- [ ] Test temporal safety
- [ ] Evaluate TCB reduction
- [ ] Report on verifier offloading feasibility

## Phase 5 — Finalization (September–December)

- [ ] Draft results chapters
- [ ] Internal review
- [ ] Final formatting and submission (Dec 18, 2026)
