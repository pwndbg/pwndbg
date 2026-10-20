from __future__ import annotations

import argparse
import shutil
import subprocess

import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Parse a struct sock_fprog from memory and dump its filter"
)
parser.add_argument(
    "addr",
    type=int,
    help="Address of sock_fprog structure in target process memory (e.g. 0xdeadbeef)",
)


def _parse_seccomp(filter_addr: int, filter_len: int) -> str:
    filter_size = filter_len * 8
    filter_bytes = pwndbg.aglib.memory.read(filter_addr, filter_size, partial=False)
    if shutil.which("ceccomp"):
        proc = subprocess.run(
            ["ceccomp", "disasm", "--color", "always"], input=filter_bytes, capture_output=True
        )
        return proc.stdout.decode() or proc.stderr.decode()
    if shutil.which("seccomp-tools"):
        proc = subprocess.run(
            ["seccomp-tools", "disasm", "-"], input=filter_bytes, capture_output=True
        )
        return proc.stdout.decode() or proc.stderr.decode()
    return "install ceccomp or seccomp-tools to parse seccomp"


@pwndbg.commands.Command(parser, command_name="parse-seccomp", category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def parse_seccomp(addr: int) -> None:
    """Parse a struct sock_fprog at a given address and pass filter to external tool."""

    # addr = int(addr) & pwndbg.aglib.arch.ptrmask
    filter_len = pwndbg.aglib.memory.u16(addr)
    filter_addr = pwndbg.aglib.memory.u(addr + pwndbg.aglib.typeinfo.ptrsize)

    print(message.success(f"sock_fprog @ {addr:#x}"))
    print(f"  len          = {filter_len}")
    print(f"  filter_addr  = {filter_addr:#x}")
    print(_parse_seccomp(filter_addr, filter_len))
