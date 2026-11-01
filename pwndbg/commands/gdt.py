from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.commands
from pwndbg import color
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""Decode X86-64 GDT entries at address

See also:

* https://wiki.osdev.org/Global_Descriptor_Table
* https://wiki.osdev.org/GDT_Tutorial
""",
)

parser.add_argument(
    "address",
    type=int,
    help="x86-64 GDTR base address (e.g. read from sgdt instruction from [16:79] bits)",
)

parser.add_argument(
    "count",
    nargs="?",
    default=8,
    help="Number of entries to dump (should be (GDTR.size+1)/8)",
    type=int,
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MEMORY,
    notes="""
In 64-bit mode, the Base and Limit values are ignored, each descriptor covers
the entire linear address space regardless of what they are set to.
""",
)
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

    # Separate the top DWORD so the bit numbers match with the ones
    # in the "Intel 64 and IA-32 Architectures Software Developer's Manual"
    top_dword = value >> 32


    # Granularity flag
    g_bit = (top_dword & (1 << 23)) >> 23

    # Default operation size/default stack pointer size and/or upper bound flag
    db_bit = (top_dword & (1 << 22)) >> 22

    # 64-bit code segment) flag
    l_bit = (top_dword & (1 << 21)) >> 21

    # The bit available for use by system software
    avl_bit = (top_dword & (1 << 20)) >> 20


    # Segment-present flag
    # Must be set for a valid segment
    p_bit = (top_dword & (1 << 15)) >> 15

    # Descriptor privilege level; 0 == kernel, 3 == userspace
    dpl_bits = (top_dword & (0b11 << 13)) >> 13

    # Descriptor type flag
    s_bit = (top_dword & (1 << 12)) >> 12


    # If 0 - data segment, if 1 - code segment
    type_dc_bit = (top_dword & (1 << 11)) >> 11

    # For data: expand-down bit
    # For code: conforming bit
    type_ec_bit = (top_dword & (1 << 10)) >> 10

    # For data: if 0 - read-only, if 1 - read/write
    # For code: if 0 - execute-only, if 1 - execute/read
    type_wr_bit = (top_dword & (1 << 9)) >> 9

    # Accessed bit
    # If GDT descriptor is stored in RO pages and this bit is 0
    # the CPU trying to set this bit will trigger page fault
    type_aa_bit = (top_dword & (1 << 8)) >> 8

    colorme = lambda label, val: (color.green if val else color.red)(label)

    flags_str = "|".join(
        (
            colorme("G", g_bit),
            colorme("D/B", db_bit),
            colorme("L", l_bit),
            colorme("AVL", avl_bit),
        )
    )

    access_str = "|".join(
        (
            colorme("P", p_bit),
            f"DPL:{dpl_bits}",
            colorme("S", s_bit),
        )
    )

    type_str = ""

    if type_dc_bit == 1:
        type_str = "Code:" + "|".join(
            (
                #                  v
                colorme("C", type_ec_bit),
                colorme("R", type_wr_bit),
                colorme("A", type_aa_bit),
            )
        )
    else:
        type_str = "Data:" + "|".join(
            (
                #                 v
                colorme("E", type_ec_bit),
                colorme("W", type_wr_bit),
                colorme("A", type_aa_bit),
            )
        )

    # If granularity bit if set, then the limit represents
    # the number of 4KB pages
    if g_bit == 1:
        limit = (limit << 12) | 0xFFF

    return f"base={base:#4x}, limit={limit:#8x}, flags={flags_str}, access={access_str}, type={type_str}"
