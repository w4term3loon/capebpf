#!/usr/bin/env python3
"""Manage the local Morello CheriBSD VM used by this repository.

The Docker image ships cheribuild's vendored pexpect, but not as an installed
Python package.  This script runs inside the container and uses that vendored
copy to drive QEMU's serial console when normal multi-user boot hangs.
"""

from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import time
from pathlib import Path


CHERI_ROOT = Path("/opt/cheri")
QEMU = CHERI_ROOT / "output/sdk/bin/qemu-system-morello"
DISK = CHERI_ROOT / "output/cheribsd-morello-purecap.qcow2"
BIOS = "edk2-aarch64-code.fd"
PEXPECT = CHERI_ROOT / "cheribuild/3rdparty/pexpect"
PTYPROCESS = CHERI_ROOT / "cheribuild/3rdparty/ptyprocess"


def import_pexpect():
    sys.path[:0] = [str(PEXPECT), str(PTYPROCESS)]
    import pexpect  # type: ignore

    return pexpect


def qemu_cmd(port: int, *, snapshot: bool = True) -> list[str]:
    netdev = (
        "user,id=net0,"
        "smb=/workspace<<<workspace,"
        f"hostfwd=tcp:127.0.0.1:{port}-:22"
    )
    cmd = [
        str(QEMU),
        "-M",
        "virt,gic-version=3",
        "-cpu",
        "morello",
        "-bios",
        BIOS,
        "-m",
        "2048",
        "-nographic",
        "-drive",
        f"if=none,file={DISK},id=drv,format=qcow2",
        "-device",
        "virtio-blk-pci,drive=drv",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-netdev",
        netdev,
        "-device",
        "virtio-rng-pci",
        "-virtfs",
        "local,id=virtfs1,mount_tag=workspace,path=/workspace,security_model=mapped-xattr",
    ]
    if snapshot:
        cmd.insert(cmd.index("-virtfs"), "-snapshot")
    return cmd


def kill_existing() -> None:
    subprocess.run(["pkill", "-f", "qemu-system-morello"], check=False)
    subprocess.run(["pkill", "-f", "cheribuild.py run-morello-purecap"], check=False)


def wait_ssh(port: int, timeout_s: int) -> bool:
    deadline = time.time() + timeout_s
    cmd = [
        "ssh",
        "-p",
        str(port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "root@localhost",
        "exit",
    ]
    while time.time() < deadline:
        if subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return True
        time.sleep(5)
    return False


def boot_multi(args: argparse.Namespace) -> int:
    kill_existing()
    cmd = qemu_cmd(args.port, snapshot=not args.persistent)
    log = Path(args.log)
    with log.open("wb") as f:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT)
    print(f"started qemu pid={proc.pid}, log={log}")
    if wait_ssh(args.port, args.timeout):
        print("ssh ready")
        return 0
    print("ssh not ready before timeout")
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    kill_existing()
    return 1


def run_guest_command(child, command: str, timeout: int) -> int:
    marker = "__CHERI_VM_RC:"
    child.sendline(f"{command}; printf '\\n{marker}%d__\\n' $?")
    child.expect(marker + r"([0-9]+)__", timeout=timeout)
    rc = int(child.match.group(1))
    child.expect(["# "], timeout=30)
    if rc != 0:
        print(f"guest command failed with rc={rc}: {command}", file=sys.stderr)
    return rc


def boot_single_command(args: argparse.Namespace) -> int:
    pexpect = import_pexpect()
    kill_existing()
    cmd = qemu_cmd(args.port, snapshot=not args.persistent)
    child = pexpect.spawn(cmd[0], cmd[1:], encoding="utf-8", echo=False, timeout=60)
    child.logfile_read = sys.stdout
    status = 0
    try:
        idx = child.expect(["Autoboot in", "Trying to mount root", pexpect.TIMEOUT], timeout=240)
        if idx == 0:
            child.send("2")
        elif idx == 1:
            print("missed boot menu; image already booting multi-user", file=sys.stderr)
            return 2
        else:
            print("timed out before boot menu", file=sys.stderr)
            return 2

        child.expect(["Enter full pathname of shell or RETURN for /bin/sh:", pexpect.TIMEOUT], timeout=600)
        child.sendline("")
        child.expect(["# ", pexpect.TIMEOUT], timeout=180)
        for command in args.command:
            rc = run_guest_command(child, command, args.command_timeout)
            if rc != 0:
                status = rc
                break
        child.sendline("shutdown -p now")
        child.expect([pexpect.EOF, "Uptime:"], timeout=120)
        return status
    finally:
        if child.isalive():
            child.kill(signal.SIGTERM)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    stop = sub.add_parser("stop")
    stop.set_defaults(func=lambda _args: (kill_existing() or 0))

    multi = sub.add_parser("start")
    multi.add_argument("--port", type=int, default=2222)
    multi.add_argument("--timeout", type=int, default=600)
    multi.add_argument("--log", default="/workspace/cheri-vm.log")
    multi.add_argument("--persistent", action="store_true")
    multi.set_defaults(func=boot_multi)

    single = sub.add_parser("single-command")
    single.add_argument("--port", type=int, default=2222)
    single.add_argument("--command-timeout", type=int, default=180)
    single.add_argument("--persistent", action="store_true")
    single.add_argument("command", nargs="+")
    single.set_defaults(func=boot_single_command)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
