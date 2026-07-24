# CHERI-eBPF JIT Prototype

This repository is a research prototype for one narrow claim:

> A CHERI-aware eBPF JIT can turn selected verifier-missed spatial memory bugs
> into deterministic hardware traps while still executing valid generated eBPF.

The project uses uBPF on CheriBSD/Morello instead of the in-kernel Linux eBPF
runtime. That keeps the experiment focused on the JIT translation and native
memory execution path. It is not a replacement for the Linux verifier. The
verifier still owns program admission, termination, helper policy, type rules,
and control-flow restrictions.

## Current Scope

The current implementation supports a conservative CHERI JIT subset:

- scalar values remain integer values;
- context and stack pointers are tracked as CHERI capabilities;
- capability arithmetic is allowed only from tracked capability roots plus scalar
  offsets;
- unsupported memory operations fail during CHERI translation;
- in-bounds generated BPF context/stack accesses execute normally;
- out-of-bounds generated BPF context/stack accesses trap under CHERI bounds.

The main generated-BPF result is currently:

| Category | Cases | Result |
| --- | ---: | --- |
| Valid generated BPF | 6/6 | returned expected values |
| OOB generated BPF | 4/4 | trapped with `signal=34 code=1` |
| Unexpected failures | 0 | none |

## Repository Layout

```text
.
|-- Dockerfile                         CheriBSD/Morello SDK container
|-- Makefile                           build, VM, and test targets
|-- proposal.pdf                       original thesis proposal
|-- JIT_PORT.md                        CHERI JIT port contract
|-- JIT_PLAN.md                        implementation sequence notes
|-- PLAN.md                            current roadmap notes
|-- docs/                              captured results and milestone notes
|-- tools/                             VM and object-JIT helper scripts
`-- workspace/                         VM-mounted source and tests
    |-- README.md                      workspace file guide
    |-- bpf/                           generated eBPF C fixtures
    |-- test_cheri_generated_bpf.c     generated-BPF CHERI JIT harness
    |-- test_cheri_translate_reject.c  CHERI translator accept/reject suite
    `-- ubpf/                          uBPF submodule
```

## Reproduction

Initialize the submodule and Docker environment:

```sh
git submodule update --init --recursive
make init
```

Run host-side baseline checks:

```sh
make host-check
```

Run the current CHERI regression suite:

```sh
sg docker -c 'make cheri-check'
```

Inspect and run the generated-BPF CHERI JIT suite directly:

```sh
make -B compile-generated-bpf
sg docker -c 'make run-cheri-generated-bpf'
```

## Current Primary Evidence

Read these first:

- `docs/project_state.md`: current audit and known limitations.
- `docs/generated_bpf_cheri_jit_milestone.md`: generated C-to-BPF-to-CHERI-JIT
  result and fixture split.
- `docs/cve_performance_exploration.md`: CVE and performance exploration notes.

Older documents in `docs/` are retained as research notes. Treat them as
historical unless they are repeated in `docs/project_state.md` or the generated
BPF milestone.

## Known Limits

The prototype does not yet cover helper calls, maps, packet pointers,
helper-returned pointer types, local calls, or atomics in the generated-BPF
suite. The next practical artifact is a side-by-side host/x86 versus CHERI
comparison harness over the same generated fixtures.
