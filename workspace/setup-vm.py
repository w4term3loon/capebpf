#!/usr/bin/env python3
"""Boot Morello QEMU VM, log in via serial console, and install SSH key."""

import os, pty, select, time, sys, fcntl, termios

pubkey = open("/home/cheri/.ssh/id_ed25519.pub").read().strip()
log = open("/tmp/setup.log", "wb")

child_pid, fd = pty.fork()
if child_pid == 0:
    os.execvp("/opt/cheri/output/sdk/bin/qemu-system-morello", [
        "qemu-system-morello",
        "-M", "virt,gic-version=3", "-cpu", "morello",
        "-bios", "edk2-aarch64-code.fd", "-m", "2048", "-nographic",
        "-drive", "if=none,file=/opt/cheri/output/cheribsd-morello-purecap.qcow2,id=drv,format=qcow2",
        "-device", "virtio-blk-pci,drive=drv",
        "-device", "virtio-net-pci,netdev=net0",
        "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22",
        "-device", "virtio-rng-pci",
    ])
else:
    output = b""
    login_done = False
    setup_done = False
    start_time = time.time()
    timeout = 1800  # 30 minutes max boot wait

    # Set the PTY to raw mode so we don't get stuck
    attr = termios.tcgetattr(fd)
    attr[3] = attr[3] & ~(termios.ECHO | termios.ICANON | termios.ISIG)
    attr[2] = attr[2] & ~termios.HUPCL
    termios.tcsetattr(fd, termios.TCSADRAIN, attr)

    while True:
        elapsed = time.time() - start_time
        if elapsed > timeout:
            print(f"TIMEOUT after {elapsed:.0f}s", flush=True)
            break

        r, _, _ = select.select([fd], [], [], 1.0)
        if r:
            try:
                data = os.read(fd, 4096)
                if not data:
                    break
                output += data
                log.write(data)
                log.flush()
            except:
                break

        text = output.decode(errors="replace")

        # Show progress every 30s
        if int(elapsed) % 30 == 0 and int(elapsed) > 0:
            last_line = [l for l in text.split("\n") if l.strip()]
            print(f"  [{elapsed:.0f}s] last line: {last_line[-1][:80] if last_line else '(none)'}", flush=True)

        if not login_done:
            if "login:" in text:
                print(f"[{elapsed:.0f}s] Got login prompt, sending credentials...", flush=True)
                output = b""
                time.sleep(2)
                os.write(fd, b"root\n")
                time.sleep(2)

            if "Password:" in text:
                print(f"[{elapsed:.0f}s] Got password prompt...", flush=True)
                output = b""
                time.sleep(1)
                os.write(fd, b"root\n")
                time.sleep(3)

            # Match both # and $ prompts (CheriBSD uses # for root)
            if "root@" in text and ("# " in text or "$ " in text):
                print(f"[{elapsed:.0f}s] Shell prompt detected, installing SSH key...", flush=True)
                output = b""
                login_done = True
                cmd = (
                    f"mkdir -p /root/.ssh && "
                    f"echo '{pubkey}' > /root/.ssh/authorized_keys && "
                    f"chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && "
                    f"echo SETUP_DONE\n"
                )
                os.write(fd, cmd.encode())
                time.sleep(3)

        if login_done and b"SETUP_DONE" in output:
            print(f"[{elapsed:.0f}s] SSH key installed successfully!", flush=True)
            output = b""
            setup_done = True
            break

    if not setup_done:
        print(f"VM setup incomplete after {elapsed:.0f}s", flush=True)
        # Keep VM running anyway, maybe SSH will become available

    print(f"VM is running. SSH port 2222 forwarded.", flush=True)
    print(f"SSH command: ssh -p 2222 root@localhost", flush=True)
    # Don't close the PTY or kill QEMU - keep it running
    while True:
        time.sleep(10)
        # Read any remaining output
        try:
            r, _, _ = select.select([fd], [], [], 1.0)
            if r:
                data = os.read(fd, 4096)
                if data:
                    log.write(data)
                    log.flush()
        except:
            pass
