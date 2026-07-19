from __future__ import annotations

import argparse

import pwndbg
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Switch QEMU between physical and virtual memory modes, or show current mode."
)
parser.add_argument(
    "mode",
    nargs="?",
    type=str,
    choices=["phys", "virt"],
    help="Memory mode to switch to. Omit to show current mode.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
def qemu_mem_mode(mode: str | None = None) -> None:
    inferior = pwndbg.dbg.selected_inferior()
    if mode is None:
        val = inferior.send_remote("qqemu.PhyMemMode").decode()
        current = "phys" if val == "1" else "virt"
        print(message.notice(f"Current QEMU memory mode: {current}"))
        return

    packet = "Qqemu.PhyMemMode:1" if mode == "phys" else "Qqemu.PhyMemMode:0"
    inferior.send_remote(packet)
    check = inferior.send_remote("qqemu.PhyMemMode").decode()
    expected = "1" if mode == "phys" else "0"
    if check == expected:
        print(message.success(f"Switched to {mode} memory mode."))
    else:
        print(message.error(f"Failed to switch to {mode} memory mode."))


phys_read_parser = argparse.ArgumentParser(
    description="Read memory from a physical address by temporarily switching to physical mode."
)
phys_read_parser.add_argument("addr", type=int, help="Physical address to read from")
phys_read_parser.add_argument("size", type=int, help="Number of bytes to read")


@pwndbg.commands.Command(phys_read_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
def physread(addr: int, size: int) -> None:
    inferior = pwndbg.dbg.selected_inferior()
    oldval = inferior.send_remote("qqemu.PhyMemMode").decode()
    inferior.send_remote("Qqemu.PhyMemMode:1")
    try:
        data = inferior.read_memory(addr, size)
        print(data.hex())
    finally:
        inferior.send_remote(f"Qqemu.PhyMemMode:{oldval}")


phys_write_parser = argparse.ArgumentParser(
    description="Write a value to a physical address by temporarily switching to physical mode."
)
phys_write_parser.add_argument("addr", type=int, help="Physical address to write to")
phys_write_parser.add_argument("value", type=int, help="Integer value to write")
phys_write_parser.add_argument(
    "--size", type=int, default=8, help="Number of bytes to write (default: 8)"
)


@pwndbg.commands.Command(phys_write_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
def physwrite(addr: int, value: int, size: int = 8) -> None:
    inferior = pwndbg.dbg.selected_inferior()
    oldval = inferior.send_remote("qqemu.PhyMemMode").decode()
    inferior.send_remote("Qqemu.PhyMemMode:1")
    try:
        inferior.write_memory(addr, bytearray(value.to_bytes(size, "little")))
        print(message.success(f"Wrote {hex(value)} to physical address {hex(addr)}."))
    finally:
        inferior.send_remote(f"Qqemu.PhyMemMode:{oldval}")
