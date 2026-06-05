# CHERI-eBPF: Hardware-Enforced Memory Safety for eBPF

This repository holds the experimental infrastructure for my Master's thesis
proposal: **offloading the Linux eBPF verifier's memory safety checks to CHERI
hardware capabilities on Arm Morello**.

## The Problem

The Linux eBPF verifier is a 20k+ line static analyser that must prove every
program safe before execution. Despite its complexity, logic bugs (e.g.,
CVE-2023-2163, CVE-2021-4204) let malicious bytecode bypass checks and corrupt
kernel memory. The verifier has become a vulnerability surface rather than a
solution.

## The Proposal

Replace the eBPF arm64 JIT compiler's 64-bit integer registers with CHERI's
**128-bit capabilities**. Every memory access then carries hardware-enforced
bounds and permissions. Even if the verifier misses a bug, an OOB access
triggers an immediate capability exception — no software check needed.

## Repository Structure

```
├── Dockerfile          # CheriBSD + Morello QEMU SDK image
├── Makefile            # All targets (init, compile, run, …)
├── proposal.pdf        # Full thesis proposal
├── workspace/
│   ├── test.c          # OOB demo (standard C)
│   ├── test_binary     # Pre-compiled test (gitignored)
│   └── ubpf/           # uBPF userspace eBPF VM (git submodule)
└── README.md
```

## HOWTO

### Prerequisites

- Docker
- `clang` (host-side, for `make compile-bpf`)
- `git submodule` support

### Quick start

```sh
# 1. Clone and initialise submodules
git submodule update --init --recursive

# 2. Build Docker image and start the container
make init

# 3. Boot the Morello QEMU VM (waits until SSH is ready)
make start-vm

# 4. Cross-compile uBPF for pure-capability CheriBSD
make compile-ubpf

# 5. Cross-compile a plain C test
make compile SRC=test.c BIN=test_binary

# 6. Copy it to the VM and run it
make run BIN=test_binary

# 7. Jump into the VM interactively
make ssh
```

### Compiling and running eBPF programs

```sh
# Write eBPF C code, compile to eBPF bytecode with host clang
make compile-bpf SRC=my_prog.c BIN=my_prog.o

# Run it through the uBPF interpreter or JIT on the VM
make run BIN=my_ubpf_test
```

### Day-to-day cycle

```sh
make start-vm          # if the VM isn't running
make compile SRC=... BIN=...   # rebuild
make run BIN=...       # re-test
```

### Cleanup

```sh
make clean             # stop and remove the container
```

## Makefile Reference

| Target | Description |
|---|---|
| `init` | Build Docker image + start container |
| `submodule-init` | `git submodule update --init --recursive` |
| `start-vm` | Boot QEMU VM in background, wait for SSH |
| `vm-ready` | Poll SSH until the VM is reachable |
| `console` | Boot VM with interactive serial console |
| `debug-gdb` | Boot VM + pause for GDB (port 1234) |
| `compile SRC= BIN=` | Cross-compile C for purecap |
| `compile-ubpf` | Cross-compile uBPF core into `libubpf.a` |
| `compile-bpf SRC= BIN=` | Compile C to eBPF bytecode (host clang) |
| `run BIN=` | SCP binary to VM + execute |
| `ssh` | Interactive SSH session into VM |
| `status` | Show container + VM health |
| `clean` | Stop and remove container |
