from __future__ import annotations

import argparse
from typing import Optional
from typing import Tuple

import pwndbg.aglib.asm
import pwndbg.aglib.file
from pwndbg.commands import CommandCategory

# Taken from linux/arch/x86/include/asm/msr-index.h
# Arbitrary list, feel free to add more.
X86_MSRS = {
    "MSR_EFER": 0xC0000080,
    "MSR_STAR": 0xC0000081,
    "MSR_LSTAR": 0xC0000082,
    "MSR_CSTAR": 0xC0000083,
    "MSR_SYSCALL_MASK": 0xC0000084,
    "MSR_FS_BASE": 0xC0000100,
    "MSR_GS_BASE": 0xC0000101,
    "MSR_KERNEL_GS_BASE": 0xC0000102,
    "MSR_TSC_AUX": 0xC0000103,
}


COMMON_MSRS = {"i386": X86_MSRS, "x86-64": X86_MSRS}


def parse_msr(msr: str, arch: str) -> Optional[int]:
    # first try to parse MSR name, then as int/hex
    if (val := COMMON_MSRS.get(arch, {}).get(msr.upper())) is not None:
        return val

    try:
        return int(msr, 0)
    except ValueError:
        print(f"unknown MSR {msr} on {arch}")
        return None


def parse_range(msr_range: str, arch: str) -> Optional[Tuple[int, int]]:
    bounds = msr_range.split("-")
    if len(bounds) != 2:
        return None

    start = parse_msr(bounds[0], arch)
    end = parse_msr(bounds[1], arch)

    if start is None or end is None:
        return None

    if start > end:
        return None

    return (start, end)


def x86_msr_read(msr: int) -> None:
    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        sc = pwndbg.aglib.asm.asm(f"mov ecx, {msr}; rdmsr")
        async with pwndbg.aglib.shellcode.exec_shellcode(ec, sc):
            edx = int(pwndbg.aglib.regs["edx"]) << 32
            eax = int(pwndbg.aglib.regs["eax"])
            ret = edx + eax
            print(f"{hex(msr)}:\t{hex(ret)}")

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


def x86_msr_write(msr: int, write_value: int) -> None:
    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        eax = write_value & 0xFFFFFFFF
        edx = write_value >> 32
        sc = pwndbg.aglib.asm.asm(f"mov ecx, {msr}; mov eax, {eax}; mov edx, {edx}; wrmsr")
        async with pwndbg.aglib.shellcode.exec_shellcode(ec, sc):
            return

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


def msr_read(msr: int) -> None:
    arch = pwndbg.aglib.arch.name

    if arch == "i386" or arch == "x86-64":
        x86_msr_read(msr)
    else:
        print(f"{arch} not supported")


def msr_write(msr: int, write_value: int) -> None:
    arch = pwndbg.aglib.arch.name

    if arch == "i386" or arch == "x86-64":
        x86_msr_write(msr, write_value)
    else:
        print(f"{arch} not supported")


def msr_list(arch: str):
    msrs = COMMON_MSRS[arch]
    longest_msr_name = max(map(len, msrs))
    for msr, value in msrs.items():
        print(f"{msr.ljust(longest_msr_name)} = {hex(value)}")


parser = argparse.ArgumentParser(
    description="""
Read or write to Model Specific Register (MSR)
""",
)
parser.add_argument("msr", help="MSR value or name", type=str, nargs="?", default=None)
parser.add_argument(
    "-w",
    "--write",
    metavar="write_value",
    help="value to write in MSR",
    type=int,
    nargs="?",
    default=None,
)
parser.add_argument(
    "-l",
    "--list",
    dest="list_msr",
    action="store_true",
    help="list common MSRs for the current arch",
    default=False,
)
parser.add_argument(
    "-r",
    "--range",
    dest="msr_range",
    help="dash separated range of MSRs to read (eg. --range=1-10 where 10 is included)",
    type=str,
    nargs="?",
    default=None,
)


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
def msr(
    msr: Optional[str] = None,
    write: Optional[int] = None,
    list_msr=False,
    msr_range: Optional[str] = None,
) -> None:
    arch = pwndbg.aglib.arch.name

    if msr:
        msr_val = parse_msr(msr, arch)
        if msr_val is None:
            print(f"Error: failed to parse {msr}")
            return

        if write:
            msr_write(msr_val, write)
            return

        msr_read(msr_val)

    elif msr_range:
        parsed_range = parse_range(msr_range, arch)
        if not parsed_range:
            print("Error: invalid range")
            return

        for m in range(parsed_range[0], parsed_range[1] + 1):
            msr_read(m)

    elif list_msr:
        msr_list(arch)

    else:
        parser.print_usage()
