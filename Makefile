IMAGE_NAME = custom-cheribsd-morello
CONTAINER_NAME = thesis-workspace
PORT = 2222
GDB_PORT = 1234
WORKSPACE = $(PWD)/workspace
SSH_OPTS = -p $(PORT) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR

UBPF_SRCDIR = workspace/ubpf
UBPF_BUILDDIR = workspace/ubpf/build
UBPF_CORE = \
	vm/ubpf_vm.c \
	vm/ubpf_loader.c \
	vm/ubpf_jit.c \
	vm/ubpf_jit_support.c \
	vm/ubpf_jit_arm64.c \
	vm/ubpf_instruction_valid.c

CHERI_CLANG = /opt/cheri/output/morello-sdk/bin/clang
CHERI_CFG = /opt/cheri/output/morello-sdk/bin/cheribsd-morello-purecap.cfg

.PHONY: init submodule-init start-vm vm-ready console debug-gdb \
	compile compile-ubpf compile-ubpf-test compile-bpf run ssh status clean

# Container lifecycle

init: submodule-init
	docker build -t $(IMAGE_NAME) .
	docker run -d --name $(CONTAINER_NAME) \
		-v $(WORKSPACE):/workspace \
		-p $(PORT):$(PORT) \
		$(IMAGE_NAME) tail -f /dev/null

submodule-init:
	git submodule update --init --recursive

# VM lifecycle

start-vm:
	docker exec -d $(CONTAINER_NAME) \
		/opt/cheri/cheribuild/cheribuild.py run-morello-purecap \
		--run/ssh-forwarding-port $(PORT)
	@echo "Booting VM (this takes ~30-60s)..."
	@$(MAKE) --no-print-directory vm-ready

vm-ready:
	@echo -n "Waiting for VM SSH (this can take 10+ min on first boot)"
	@for i in $$(seq 1 90); do \
		docker exec $(CONTAINER_NAME) ssh $(SSH_OPTS) root@localhost "exit" 2>/dev/null && \
			echo " ready ($$((i * 10))s)" && exit 0; \
		echo -n "."; \
		[ $$((i % 6)) -eq 0 ] && echo -n "$$((i * 10))s"; \
		sleep 10; \
	done; \
	echo " timeout"; exit 1

console:
	docker exec -it $(CONTAINER_NAME) \
		/opt/cheri/cheribuild/cheribuild.py run-morello-purecap \
		--run/ssh-forwarding-port $(PORT)

debug-gdb:
	docker exec -it $(CONTAINER_NAME) \
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

compile-ubpf-test:
	docker exec $(CONTAINER_NAME) \
		$(CHERI_CLANG) --config $(CHERI_CFG) \
		-o /workspace/ubpf_test \
		-I/workspace/ubpf/vm \
		-I/workspace/ubpf/vm/inc \
		/workspace/ubpf_test.c \
		/workspace/ubpf/build/libubpf.a

compile-bpf:
	clang -O2 -target bpf -c $(WORKSPACE)/$(SRC) -o $(WORKSPACE)/$(BIN)

# Execution

run: vm-ready
	docker exec $(CONTAINER_NAME) \
		scp $(SSH_OPTS) /workspace/$(BIN) root@localhost:/root/
	docker exec $(CONTAINER_NAME) \
		ssh $(SSH_OPTS) root@localhost "/root/$(BIN)"; \
		status=$$?; \
		echo "Exit code: $$status"; \
		exit $$status

ssh:
	docker exec -it $(CONTAINER_NAME) \
		ssh $(SSH_OPTS) root@localhost

# Utilities

status:
	@echo "=== Container ==="
	@docker inspect $(CONTAINER_NAME) --format '{{.State.Status}}' 2>/dev/null || echo "not found"
	@echo "=== VM ==="
	@docker exec $(CONTAINER_NAME) ssh $(SSH_OPTS) root@localhost "uname -a" 2>/dev/null || echo "VM not reachable"

clean:
	docker stop $(CONTAINER_NAME) || true
	docker rm $(CONTAINER_NAME) || true
