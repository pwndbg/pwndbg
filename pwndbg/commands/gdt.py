from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.color as C
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""Decode X86-64 GDT entries at address

See also:
* https://wiki.osdev.org/Global_Descriptor_Table
* https://wiki.osdev.org/GDT_Tutorial

Note:
In 64-bit mode, the Base and Limit values are ignored, each descriptor covers the entire linear address space regardless of what they are set to.
""",
)

parser.add_argument(
    "address",
    type=int,
    help="x86-64 GDTR base address (e.g. read from sgdt instruction from [16:79] bits)",
)

parser.add_argument(
    "count", nargs="?", default=8, help="Number of entries to dump (should be (GDTR.size+1)/8)"
)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.aglib.proc.OnlyWithArch(["x86-64"])
def gdt(address, count) -> None:
    address = int(address)
    count = int(count)
    idx = 0

    print("Dumping GDT entries:")

    while idx < count:
        addr = address + idx * 8
        value = pwndbg.aglib.memory.u64(addr)
        e = decode_gdt_entry(value)

        print(f"{addr:#x} => {e}")
        idx += 1


def decode_gdt_entry(value):
    if value == 0:
        return "<NULL entry>"

    limit_low = value & 0xFFFF
    limit_high = (value >> 48) & 0xF
    limit = (limit_high << 16) | limit_low

    base_low = (value >> 16) & 0xFFFF
    base_mid = (value >> 32) & 0xFF
    base_high = (value >> 56) & 0xFF
    base = (base_high << 24) | (base_mid << 16) | base_low

    access_byte = (value >> 40) & 0xFF

    flags = (value >> 52) & 0xF

    # If GDT descriptor is stored in RO pages and this bit is 0
    # the CPU trying to set this bit will trigger page fault
    accessed_bit = access_byte & (1 << 0)

    # If 0, read (code segment) or write (data segment) access is not allowed
    # (Read is always allowed for data; write is never allowed for code segment)
    rw_bit = (access_byte & (1 << 1)) >> 1

    # Direction bit/Conforming bit
    dc_bit = (access_byte & (1 << 2)) >> 2

    # If 0 == data segment, if 1 == code segment
    exec_bit = (access_byte & (1 << 3)) >> 3

    # Descriptor type; 0 == system segment, 1 == code or data segment
    type_bit = (access_byte & (1 << 4)) >> 4

    # Descriptor privilege level; 0 == kernel, 3 == userspace
    dpl_bits = (access_byte & (0b11 << 5)) >> 5

    # Must be set for a valid segment
    present_bit = (access_byte & (1 << 7)) >> 7

    colorme = lambda label, val: (C.green if val else C.red)(label)

    access_str = "|".join(
        (
            colorme("P", present_bit),
            f"DPL:{dpl_bits}",
            colorme("S", type_bit),
            colorme("E", exec_bit),
            colorme("DC", dc_bit),
            colorme("RW", rw_bit),
            colorme("A", accessed_bit),
        )
    )

    flags_str = "|".join(
        (
            colorme("G", (flags & (1 << 3)) >> 3),
            colorme("DB", (flags & (1 << 2)) >> 2),
            colorme("L", (flags & (1 << 1)) >> 1),
        )
    )

    return f"base={base:#4x}, limit={limit:#8x}, access={access_str}, flags={flags_str}"
