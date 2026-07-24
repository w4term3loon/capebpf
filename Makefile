IMAGE_NAME = custom-cheribsd-morello
CONTAINER_NAME = thesis-workspace
PORT = 2222
GDB_PORT = 1234
WORKSPACE = $(PWD)/workspace
SSH_OPTS = -p $(PORT) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=5
SCP_OPTS = -P $(PORT) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=5

UBPF_SRCDIR = workspace/ubpf
UBPF_BUILDDIR = workspace/ubpf/build
UBPF_ELF_BUILDDIR = workspace/ubpf/build-elf
UBPF_CORE = \
	vm/ubpf_vm.c \
	vm/ubpf_loader.c \
	vm/ubpf_jit.c \
	vm/ubpf_jit_support.c \
	vm/ubpf_jit_arm64.c \
	vm/ubpf_jit_arm64_cheri.c \
	vm/ubpf_instruction_valid.c

CHERI_CLANG = /opt/cheri/output/morello-sdk/bin/clang
CHERI_CFG = /opt/cheri/output/morello-sdk/bin/cheribsd-morello-purecap.cfg
DOCKER_VM_USER = cheri
BPF_CLANG ?= clang
BPF_OBJDUMP ?= llvm-objdump
BPF_FIXTURE_SRC = workspace/bpf/stack_array.c
BPF_FIXTURE_OBJ = workspace/bpf/stack_array.o

.PHONY: init submodule-init start-vm stop-vm vm-ready console debug-gdb \
	compile compile-ubpf compile-ubpf-test compile-exploit-tests \
	compile-ubpf-elf compile-generated-bpf compile-cheri-generated-bpf run-cheri-generated-bpf \
	compile-cheri-translate-reject run-cheri-translate-reject \
	compile-cheri-context-load run-cheri-context-load \
	compile-cheri-direct-jit-repro run-cheri-direct-jit-repro \
	compile-cheri-loader-jit-repro run-cheri-loader-jit-repro \
	compile-cheri-objjit-context-repro run-cheri-objjit-context-repro \
	compile-cheri-objjit-compile run-cheri-objjit-compile \
	compile-cheri-tail-helper-context run-cheri-tail-helper-context \
	compile-bpf run run-cheri-single run-exploit-tests ssh status clean

# Container lifecycle

init: submodule-init
	docker build -t $(IMAGE_NAME) .
	docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run -d --user root --name $(CONTAINER_NAME) \
		-v $(WORKSPACE):/workspace \
		-p $(PORT):$(PORT) \
		$(IMAGE_NAME) tail -f /dev/null

submodule-init:
	git submodule update --init --recursive

# VM lifecycle

start-vm:
	docker exec $(CONTAINER_NAME) cheri-vm start --port $(PORT) --timeout 600 --log /workspace/cheri-vm.log

stop-vm:
	docker exec $(CONTAINER_NAME) cheri-vm stop

vm-ready:
	@echo -n "Waiting for VM SSH"
	@for i in $$(seq 1 120); do \
		docker exec $(CONTAINER_NAME) ssh $(SSH_OPTS) root@localhost "exit" 2>/dev/null && \
			echo " ready ($$((i * 5))s)" && exit 0; \
		echo -n "."; \
		[ $$((i % 12)) -eq 0 ] && echo -n "$$((i * 5))s"; \
		sleep 5; \
	done; \
	echo " timeout; see workspace/cheri-vm.log"; exit 1

console:
	docker exec -it -u $(DOCKER_VM_USER) $(CONTAINER_NAME) \
		/opt/cheri/cheribuild/cheribuild.py run-morello-purecap \
		--run/ephemeral \
		--run/ssh-forwarding-port $(PORT)

debug-gdb:
	docker exec -it -u $(DOCKER_VM_USER) $(CONTAINER_NAME) \
		/opt/cheri/cheribuild/cheribuild.py run-morello-purecap \
		--run/ssh-forwarding-port $(PORT) \
		--run/qemu-extra-options="-s -S"

# Compilation

compile:
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/$(BIN) /workspace/$(SRC)

compile-ubpf:
	mkdir -p $(UBPF_BUILDDIR)
	@echo "Compiling ubpf for purecap..."
	docker exec $(CONTAINER_NAME) \
		sh -c 'set -e; \
			for f in $(UBPF_CORE); do \
				$(CHERI_CLANG) --config $(CHERI_CFG) \
					-c -o /workspace/ubpf/build/$$(basename $$f .c).o \
					-I/workspace/ubpf/vm \
					-I/workspace/ubpf/vm/inc \
					/workspace/ubpf/$$f; \
			done; \
			cd /workspace/ubpf/build && \
			ar rcs libubpf.a *.o'
	@echo "Built $(UBPF_BUILDDIR)/libubpf.a"

compile-ubpf-elf:
	mkdir -p $(UBPF_ELF_BUILDDIR)
	@echo "Compiling ubpf for purecap with ELF loader support..."
	docker exec $(CONTAINER_NAME) \
		sh -c 'set -e; \
			rm -f /workspace/ubpf/build-elf/*.o /workspace/ubpf/build-elf/libubpf.a; \
			for f in $(UBPF_CORE); do \
				$(CHERI_CLANG) --config $(CHERI_CFG) -DUBPF_HAS_ELF_H \
					-c -o /workspace/ubpf/build-elf/$$(basename $$f .c).o \
					-I/workspace/ubpf/vm \
					-I/workspace/ubpf/vm/inc \
					/workspace/ubpf/$$f; \
			done; \
			cd /workspace/ubpf/build-elf && \
			ar rcs libubpf.a *.o'
	@echo "Built $(UBPF_ELF_BUILDDIR)/libubpf.a"

compile-generated-bpf:
	$(BPF_CLANG) -target bpf -O2 -g0 -c $(BPF_FIXTURE_SRC) -o $(BPF_FIXTURE_OBJ)
	$(BPF_OBJDUMP) -d $(BPF_FIXTURE_OBJ)

compile-cheri-generated-bpf: compile-generated-bpf compile-ubpf-elf
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) -DUBPF_HAS_ELF_H \
		-o /workspace/test_cheri_generated_bpf \
		-I/workspace/ubpf/vm \
		-I/workspace/ubpf/vm/inc \
		/workspace/test_cheri_generated_bpf.c \
		/workspace/ubpf/build-elf/libubpf.a

run-cheri-generated-bpf: compile-cheri-generated-bpf
	$(MAKE) --no-print-directory run-cheri-single BIN=test_cheri_generated_bpf

compile-ubpf-test:
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/ubpf_test \
		-I/workspace/ubpf/vm \
		-I/workspace/ubpf/vm/inc \
		/workspace/ubpf_test.c \
		/workspace/ubpf/build/libubpf.a

compile-exploit-tests: compile-ubpf
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/exploit_tests \
		-I/workspace/ubpf/vm \
		-I/workspace/ubpf/vm/inc \
		/workspace/exploit_tests.c \
		/workspace/ubpf/build/libubpf.a

run-exploit-tests: compile-exploit-tests
	$(MAKE) --no-print-directory run-cheri-single BIN=exploit_tests

compile-cheri-translate-reject: compile-ubpf
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/test_cheri_translate_reject \
		-I/workspace/ubpf/vm \
		-I/workspace/ubpf/vm/inc \
		/workspace/test_cheri_translate_reject.c \
		/workspace/ubpf/build/libubpf.a

run-cheri-translate-reject: compile-cheri-translate-reject
	$(MAKE) --no-print-directory run-cheri-single BIN=test_cheri_translate_reject

compile-cheri-context-load: compile-ubpf
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/test_cheri_context_load \
		-I/workspace/ubpf/vm \
		-I/workspace/ubpf/vm/inc \
		/workspace/test_cheri_context_load.c \
		/workspace/ubpf/build/libubpf.a

run-cheri-context-load: compile-cheri-context-load
	$(MAKE) --no-print-directory run-cheri-single BIN=test_cheri_context_load

compile-cheri-direct-jit-repro:
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/test_cheri_direct_jit_repro \
		/workspace/test_cheri_direct_jit_repro.c

run-cheri-direct-jit-repro: compile-cheri-direct-jit-repro
	$(MAKE) --no-print-directory run-cheri-single BIN=test_cheri_direct_jit_repro

compile-cheri-loader-jit-repro:
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-shared -fPIC \
		-o /workspace/libcheri_loader_jit_payload.so \
		/workspace/cheri_loader_jit_payload.c
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/test_cheri_loader_jit_repro \
		/workspace/test_cheri_loader_jit_repro.c

run-cheri-loader-jit-repro: compile-cheri-loader-jit-repro
	$(MAKE) --no-print-directory run-cheri-single BIN=test_cheri_loader_jit_repro

compile-cheri-objjit-context-repro: compile-cheri-objjit-artifacts
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/test_cheri_objjit_context_repro \
		/workspace/test_cheri_objjit_context_repro.c

run-cheri-objjit-context-repro: compile-cheri-objjit-context-repro
	$(MAKE) --no-print-directory run-cheri-single BIN=test_cheri_objjit_context_repro

compile-cheri-objjit-artifacts:
	python3 tools/cheri_objjit_emit.py --program-hex '79 10 08 00 00 00 00 00 95 00 00 00 00 00 00 00' --output workspace/cheri_objjit_offset_8.S
	python3 tools/cheri_objjit_emit.py --program-hex '79 10 00 10 00 00 00 00 95 00 00 00 00 00 00 00' --output workspace/cheri_objjit_offset_4096.S
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-shared -fPIC \
		-o /workspace/cheri_objjit_offset_8.so \
		/workspace/cheri_objjit_offset_8.S
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-shared -fPIC \
		-o /workspace/cheri_objjit_offset_4096.so \
		/workspace/cheri_objjit_offset_4096.S

compile-cheri-objjit-compile: compile-ubpf compile-cheri-objjit-artifacts
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/test_cheri_objjit_compile \
		-I/workspace/ubpf/vm \
		-I/workspace/ubpf/vm/inc \
		/workspace/test_cheri_objjit_compile.c \
		/workspace/ubpf/build/libubpf.a

run-cheri-objjit-compile: compile-cheri-objjit-compile
	$(MAKE) --no-print-directory run-cheri-single BIN=test_cheri_objjit_compile

compile-cheri-tail-helper-context:
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/test_cheri_tail_helper_context \
		/workspace/test_cheri_tail_helper_context.c

run-cheri-tail-helper-context: compile-cheri-tail-helper-context
	$(MAKE) --no-print-directory run-cheri-single BIN=test_cheri_tail_helper_context

# Host (non-capability) baseline: shows exploits slipping through without CHERI
UBPF_HOST_BUILDDIR = workspace/ubpf/build-host
UBPF_HOST_CORE = \
	vm/ubpf_vm.c \
	vm/ubpf_loader.c \
	vm/ubpf_jit.c \
	vm/ubpf_jit_support.c \
	vm/ubpf_jit_x86_64.c \
	vm/ubpf_instruction_valid.c
HOST_CC ?= cc
HOST_CFLAGS ?= -O2 -Wall -Wextra
HOST_UBPF_CFLAGS ?= $(HOST_CFLAGS) -Wno-cast-function-type -Wno-sign-compare -Wno-unused-function
HOST_CHERI_CFLAGS ?= $(HOST_CFLAGS) -Wno-old-style-declaration -Wno-sign-compare -Wno-unused-function -Wno-unused-variable

.PHONY: compile-ubpf-host compile-test42-host run-test42-host \
	compile-m2-tests-host run-m2-tests-host \
	compile-m2-jmp-tests-host run-m2-jmp-tests-host \
	compile-exploit-tests-host run-exploit-tests-host \
	run-cheri-translate-reject-host compile-cheri-translate-reject-host host-check cheri-check cheri-experimental cheri-mitigations

compile-ubpf-host:
	mkdir -p $(UBPF_HOST_BUILDDIR)
	@echo "Compiling ubpf for host (x86_64, no capabilities)..."
	@rm -f $(UBPF_HOST_BUILDDIR)/*.o $(UBPF_HOST_BUILDDIR)/libubpf.a
	@set -e; \
	for f in $(UBPF_HOST_CORE); do \
		$(HOST_CC) -c $(HOST_UBPF_CFLAGS) -I$(UBPF_SRCDIR)/vm -I$(UBPF_SRCDIR)/vm/inc \
			-o $(UBPF_HOST_BUILDDIR)/$$(basename $$f .c).o \
			$(UBPF_SRCDIR)/$$f; \
	done
	@cd $(UBPF_HOST_BUILDDIR) && ar rcs libubpf.a *.o
	@echo "Built $(UBPF_HOST_BUILDDIR)/libubpf.a"

compile-test42-host: compile-ubpf-host
	$(HOST_CC) $(HOST_CFLAGS) -o workspace/test42 \
		-I$(UBPF_SRCDIR)/vm -I$(UBPF_SRCDIR)/vm/inc \
		workspace/test42.c \
		$(UBPF_HOST_BUILDDIR)/libubpf.a
	@echo "Built workspace/test42"

run-test42-host: compile-test42-host
	@echo ""
	@echo "########## R0=42 BASELINE - x86_64 host ##########"
	@./workspace/test42

compile-exploit-tests-host: compile-ubpf-host
	$(HOST_CC) $(HOST_CFLAGS) -o workspace/exploit_tests_host \
		-I$(UBPF_SRCDIR)/vm -I$(UBPF_SRCDIR)/vm/inc \
		workspace/exploit_tests.c \
		$(UBPF_HOST_BUILDDIR)/libubpf.a
	@echo "Built workspace/exploit_tests_host"

run-exploit-tests-host: compile-exploit-tests-host
	@echo ""
	@echo "########## NON-CAPABILITY BASELINE (x86_64 host) ##########"
	@./workspace/exploit_tests_host

# M2: Scalar ALU tests — mov, add, sub (imm and reg)
.PHONY: compile-m2-tests run-m2-tests

compile-m2-tests: compile-ubpf
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/test_m2 \
		-I/workspace/ubpf/vm \
		-I/workspace/ubpf/vm/inc \
		/workspace/test_m2.c \
		/workspace/ubpf/build/libubpf.a

run-m2-tests: compile-m2-tests
	$(MAKE) --no-print-directory run-cheri-single BIN=test_m2

run-m2-tests-host: compile-ubpf-host
	$(HOST_CC) $(HOST_CFLAGS) -o workspace/test_m2 \
		-I$(UBPF_SRCDIR)/vm -I$(UBPF_SRCDIR)/vm/inc \
		workspace/test_m2.c \
		$(UBPF_HOST_BUILDDIR)/libubpf.a
	@echo ""
	@echo "########## M2 SCALAR ALU - x86_64 host ##########"
	@./workspace/test_m2

compile-m2-jmp-tests-host: compile-ubpf-host
	$(HOST_CC) $(HOST_CFLAGS) -o workspace/test_m2_jmp \
		-I$(UBPF_SRCDIR)/vm -I$(UBPF_SRCDIR)/vm/inc \
		workspace/test_m2_jmp.c \
		$(UBPF_HOST_BUILDDIR)/libubpf.a
	@echo "Built workspace/test_m2_jmp"

run-m2-jmp-tests-host: compile-m2-jmp-tests-host
	@echo ""
	@echo "########## M2 CONDITIONAL JUMPS - x86_64 host ##########"
	@./workspace/test_m2_jmp

compile-cheri-translate-reject-host: compile-ubpf-host
	$(HOST_CC) $(HOST_CHERI_CFLAGS) -o workspace/test_cheri_translate_reject \
		-I$(UBPF_SRCDIR)/vm -I$(UBPF_SRCDIR)/vm/inc \
		workspace/test_cheri_translate_reject.c \
		$(UBPF_SRCDIR)/vm/ubpf_jit_arm64_cheri.c \
		$(UBPF_HOST_BUILDDIR)/libubpf.a
	@echo "Built workspace/test_cheri_translate_reject"

run-cheri-translate-reject-host: compile-cheri-translate-reject-host
	@echo ""
	@echo "########## CHERI TRANSLATOR REJECTS UNSUPPORTED MEMORY OPS — host ##########"
	@./workspace/test_cheri_translate_reject

host-check: run-test42-host run-m2-tests-host run-m2-jmp-tests-host run-exploit-tests-host run-cheri-translate-reject-host

cheri-check: run-cheri-translate-reject run-cheri-generated-bpf

cheri-experimental: run-cheri-context-load

cheri-mitigations: run-cheri-tail-helper-context

compile-bpf:
	clang -O2 -target bpf -c $(WORKSPACE)/$(SRC) -o $(WORKSPACE)/$(BIN)

# Execution

run:
	$(MAKE) --no-print-directory run-cheri-single BIN=$(BIN)

run-cheri-single:
	docker exec $(CONTAINER_NAME) cheri-vm single-command \
		"mount -u /" \
		"mkdir -p /mnt" \
		"kldload -n p9fs virtio_p9fs || true" \
		"mount -t p9fs -o trans=virtio workspace /mnt" \
		"/mnt/$(BIN)"

ssh:
	docker exec -it $(CONTAINER_NAME) \
		ssh $(SSH_OPTS) root@localhost

# Utilities

status:
	@echo "=== Docker ==="; \
	if ! docker version --format 'client={{.Client.Version}} server={{.Server.Version}}' 2>/dev/null; then \
		echo "Docker daemon not reachable by this user"; \
		exit 0; \
	fi; \
	echo "=== Container ==="; \
	docker inspect $(CONTAINER_NAME) --format '{{.State.Status}}' 2>/dev/null || echo "not found"; \
	echo "=== VM ==="; \
	if docker exec $(CONTAINER_NAME) ssh $(SSH_OPTS) root@localhost "uname -a" 2>/dev/null; then \
		true; \
	else \
		echo "VM not reachable"; \
		docker exec $(CONTAINER_NAME) pgrep -af qemu-system-morello 2>/dev/null || true; \
	fi

clean:
	docker stop $(CONTAINER_NAME) || true
	docker rm $(CONTAINER_NAME) || true
