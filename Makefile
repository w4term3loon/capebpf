IMAGE_NAME = custom-cheribsd-morello
CONTAINER_NAME = thesis-workspace
PORT = 2222
WORKSPACE = $(PWD)/workspace

# 1. build the custom image and start the container
init:
	docker build -t $(IMAGE_NAME) .
	docker run -d --name $(CONTAINER_NAME) \
		-v $(WORKSPACE):/workspace \
		-p $(PORT):$(PORT) \
		$(IMAGE_NAME) tail -f /dev/null

# 2. start the QEMU VM in the background
start-vm:
	docker exec -d $(CONTAINER_NAME) \
		/opt/cheri/cheribuild/cheribuild.py run-morello-purecap \
		--run/ssh-forwarding-port $(PORT)

# start the VM and attach your terminal to the serial console
console:
	docker exec -it $(CONTAINER_NAME) \
		/opt/cheri/cheribuild/cheribuild.py run-morello-purecap \
		--run/ssh-forwarding-port $(PORT)

GDB_PORT = 1234

# start the VM, freeze execution, and wait for a GDB connection
debug-gdb:
	docker exec -it $(CONTAINER_NAME) \
		/opt/cheri/cheribuild/cheribuild.py run-morello-purecap \
		--run/ssh-forwarding-port $(PORT) \
		--run/qemu-extra-options="-s -S"

# 3. cross-compile a C file
# usage: make compile SRC=test.c BIN=test_binary
compile:
	docker exec $(CONTAINER_NAME) \
		/opt/cheri/output/morello-sdk/bin/clang \
		--config /opt/cheri/output/morello-sdk/bin/cheribsd-morello-purecap.cfg \
		-o /workspace/$(BIN) /workspace/$(SRC)

# 4. execute the binary headlessly
# usage: make run BIN=test_binary
run:
	docker exec $(CONTAINER_NAME) scp -P $(PORT) -o StrictHostKeyChecking=no /workspace/$(BIN) root@localhost:/root/
	docker exec $(CONTAINER_NAME) ssh -p $(PORT) -o StrictHostKeyChecking=no root@localhost "/root/$(BIN)"

# 5. stop and clean up the container
clean:
	docker stop $(CONTAINER_NAME) || true
	docker rm $(CONTAINER_NAME) || true
