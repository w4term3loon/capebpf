# CHERI eBPF CVE and Performance Exploration - 2026-07-22

This note captures a temporary exploration of two questions:

1. Which eBPF-security CVEs are good candidates for future CHERI/uBPF tests?
2. What can we sensibly say about uBPF performance under CHERI in the current setup?

No project source changes were kept from the exploration. A temporary benchmark
file was created, run, and removed.

## Current Baseline

The current exploit harness covers three CVE-shaped categories:

- out-of-bounds context read, currently blocked by a CHERI bounds trap;
- pointer leakage via `R0`, currently blocked by CHERI JIT register-kind policy;
- uninitialized stack read, currently mitigated by zeroing the bounded eBPF stack.

The latest verified exploit gate reported:

```text
CHERI JIT missed: 0/3
```

These are useful but still narrow. They show that the current CHERI JIT can
protect specific supported context/stack memory shapes. They do not yet prove a
complete eBPF verifier replacement.

## Additional CVE Candidates

### High-Value Candidates

#### CVE-2020-8835

NVD describes this as a Linux BPF verifier bug where 32-bit operation register
bounds were not properly restricted, leading to out-of-bounds reads and writes in
kernel memory.

Why it fits this project:

- It maps directly to the thesis claim: verifier range analysis may be wrong, but
  CHERI bounds should still prevent an escaped pointer from accessing memory
  outside its object.
- A reduced uBPF test can model the final unsafe condition without reproducing
  the full Linux verifier bug: compute a pointer that a buggy verifier might
  consider in-bounds, then perform an OOB load/store.

Source: https://nvd.nist.gov/vuln/detail/CVE-2020-8835

#### CVE-2021-3490

NVD records CVE-2021-3490 with `CWE-125` and `CWE-787`, and its references
describe invalid ALU32 bounds tracking in Linux eBPF.

Why it fits this project:

- It is another range/bounds-tracking failure leading to OOB read/write.
- It suggests a concrete test direction: ALU32-style arithmetic or bitwise
  operations that derive a pointer offset, followed by a context or stack memory
  access.

Current blocker:

- uBPF bytecode can encode the memory shape, but a faithful reproduction would
  require more verifier-model detail than the current harness has. A reduced
  "bad offset reaches memory op" test is still useful.

Source: https://nvd.nist.gov/vuln/detail/CVE-2021-3490

#### CVE-2021-31440

NVD records this as an incorrect calculation issue in the Linux kernel, with
references to the BPF verifier fix. It is commonly grouped with verifier
arithmetic/range bugs.

Why it fits this project:

- It is useful as another reduced arithmetic-to-OOB test.
- CHERI should not need to understand the verifier arithmetic bug. It only needs
  the generated memory access to be authorized by a bounded capability.

Source: https://nvd.nist.gov/vuln/detail/CVE-2021-31440

#### CVE-2023-2163

Ubuntu describes this as incorrect verifier pruning in BPF in Linux kernels
`>=5.4`, where unsafe code paths were incorrectly marked as safe, resulting in
arbitrary read/write in kernel memory. Ubuntu also notes missing precision
tracking in some verifier situations, leading to an out-of-bounds access
vulnerability.

Why it fits this project especially well:

- It maps directly to the CHERI JIT's recent branch/provenance work.
- A reduced test can model "one path preserves a bounded pointer, another path
  creates an unsafe pointer or offset, and a join reaches a memory access."
- This is probably the best next CVE-inspired test because it exercises both
  control-flow joins and memory safety.

Source: https://ubuntu.com/security/CVE-2023-2163

### Medium-Value Candidates

#### CVE-2017-16995

NVD describes this as an incorrect sign-extension issue in
`kernel/bpf/verifier.c`'s `check_alu_op`, causing memory corruption or other
impact.

Why it partially fits:

- It can be reduced to sign/zero-extension arithmetic producing a dangerous
  offset.
- CHERI would not fix the arithmetic bug itself, but it should trap if that bug
  leads to an out-of-bounds capability memory access.

Source: https://nvd.nist.gov/vuln/detail/CVE-2017-16995

#### CVE-2022-23222

NVD describes this as Linux BPF verifier pointer arithmetic being available via
certain `*_OR_NULL` pointer types, allowing local privilege gain.

Why it matters:

- This is a real pointer-kind/provenance bug, so it is thesis-relevant.

Why it is not testable yet:

- The current CHERI JIT only has context and stack capability roots.
- A meaningful test needs helper-returned or map-value pointer capabilities and
  explicit `PTR_OR_NULL`-style state. That is future work.

Source: https://nvd.nist.gov/vuln/detail/CVE-2022-23222

### Lower-Value for Current Thesis Claim

#### CVE-2021-29154

Ubuntu describes this as incorrect computation of branch displacements in Linux
BPF JIT compilers through 5.11.12, affecting the x86 BPF JIT and allowing
arbitrary code execution in kernel context.

Why it is lower priority:

- This is a machine-code emission/branch displacement bug, not primarily a BPF
  memory verifier bug.
- CHERI code bounds could help if a bad branch leaves the generated code object,
  but CHERI does not prove branch displacement calculations are correct.
- A test would be valuable for JIT robustness, but less central to the claim that
  CHERI makes eBPF memory verification easier or more complete.

Source: https://ubuntu.com/security/CVE-2021-29154

#### CVE-2021-4204

Ubuntu describes this as an eBPF ring-buffer argument validation problem that
could cause OOB memory access.

Current status:

- A reduced helper/map capability analogue is now implemented in
  `workspace/test_helper_map_cap.c`.
- It is documented in `docs/helper_map_capability_milestone.md`.
- The current fixture is not a full ring-buffer helper port, but it does cover
  the final shape: helper-returned memory root plus invalid read/write offset.

Source: https://ubuntu.com/security/CVE-2021-4204

## Recommended CVE Test Order

1. Keep extending the CVE-2023-2163-style branch/path-pruning analogue.
2. Keep extending ALU32/range-tracking inspired OOB pointer arithmetic tests for
   CVE-2020-8835, CVE-2021-3490, and CVE-2021-31440.
3. Add more OOB write cases, not only OOB reads.
4. Expand the CVE-2021-4204 helper/map analogue toward real ring-buffer helper
   semantics.
5. Add sign-extension-derived bad-offset tests for CVE-2017-16995.
6. Defer CVE-2022-23222 until helper-returned pointer nullability and
   `PTR_OR_NULL`-style state are modeled.
7. Treat CVE-2021-29154 as a separate JIT-codegen robustness topic, not as core
   evidence for verifier simplification.

## Temporary Performance Probe

A temporary benchmark program was created as `workspace/tmp_perf_probe.c`, built
for host and CheriBSD purecap, run, and then removed.

It measured three tiny uBPF programs:

- scalar arithmetic returning `42`;
- context load returning `ctx[1]`;
- stack store/load returning `42`.

The benchmark loop measured repeated calls after load/compile. Compile time was
not included.

### Host Native x86_64

Command shape:

```sh
/tmp/tmp_perf_probe_host 1000000
```

Observed output:

```text
platform=host-native sizeof_ptr=8
interp scalar         iters=1000000 total_ns=59748613 ns_per_call=59.7 sink=42000000
jit    scalar         iters=1000000 total_ns=6332096 ns_per_call=6.3 sink=42000000
interp context_load   iters=1000000 total_ns=47841549 ns_per_call=47.8 sink=14431196722575858112
jit    context_load   iters=1000000 total_ns=6474842 ns_per_call=6.5 sink=14431196722575858112
interp stack          iters=1000000 total_ns=67249772 ns_per_call=67.2 sink=42000000
jit    stack          iters=1000000 total_ns=6340870 ns_per_call=6.3 sink=42000000
```

Host-native ratio, roughly:

- scalar JIT is about `9.5x` faster than interpreter;
- context-load JIT is about `7.4x` faster than interpreter;
- stack JIT is about `10.7x` faster than interpreter.

### CheriBSD Morello Purecap Under QEMU

Command shape:

```sh
sg docker -c 'docker exec thesis-workspace cheri-vm single-command ... "/mnt/tmp_perf_probe_cheri 100000"'
```

Observed output:

```text
platform=cheribsd-morello-purecap-qemu sizeof_ptr=16
interp scalar         iters=100000 total_ns=2773230368 ns_per_call=27732.3 sink=4200000
jit    scalar         iters=100000 total_ns=1732058224 ns_per_call=17320.6 sink=4200000
jit    context_load   iters=100000 total_ns=1740269024 ns_per_call=17402.7 sink=16200514931225227104
jit    stack          iters=100000 total_ns=1718923120 ns_per_call=17189.2 sink=4200000
```

CheriBSD/QEMU ratio, roughly:

- scalar CHERI JIT is about `1.6x` faster than the purecap interpreter in this
  temporary probe.
- CHERI JIT context and stack cases were similar to scalar JIT in this
  microbenchmark.

The purecap interpreter was not measured for context/stack in this temporary
probe because the current purecap interpreter path still contains provenance-free
integer-to-pointer memory accesses for those shapes.

## Performance Interpretation

It is not scientifically meaningful to compare native x86_64 timings directly
against CheriBSD/Morello timings from QEMU. That mixes:

- different ISA;
- different OS;
- different ABI and pointer width;
- native execution versus emulation;
- stock uBPF JIT maturity versus the experimental CHERI backend;
- Morello capability semantics and sentry entry overhead;
- QEMU timing noise.

Defensible comparisons are:

- x86 host interpreter versus x86 host JIT;
- CheriBSD/QEMU interpreter versus CheriBSD/QEMU CHERI JIT for supported scalar
  shapes;
- CHERI JIT scalar versus CHERI JIT context/stack memory shapes;
- later, Morello hardware purecap versus Morello non-purecap on the same board,
  if hardware is available.

For thesis purposes, the current performance claim should stay conservative:

> The current CHERI JIT prototype has measurable overhead in the available
> CheriBSD/QEMU setup and is not yet a performance-optimized backend. The useful
> result at this stage is functional: bounded direct-JIT memory operations are
> enforced by CHERI for the supported context/stack roots. Performance should be
> evaluated with within-platform ratios, not native-x86 versus QEMU-CHERI
> absolute timings.

