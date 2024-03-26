from __future__ import annotations

import argparse

import gdb

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.gdblib.kernel
import pwndbg.gdblib.memory
import pwndbg.gdblib.vmmap
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.config import config

parser = argparse.ArgumentParser(description="Finds the kernel virtual base address.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def kbase() -> None:
    if config.kernel_vmmap == "none":
        print(M.error("kbase does not work when kernel-vmmap is set to none"))
        return

    arch_name = pwndbg.gdblib.arch.name
    if arch_name == "x86-64":
        # 0x48 first opcode in older kernels
        # 0xFC first opcode in newer kernels
        magic = [0x48, 0x49, 0xFC]
    elif arch_name == "aarch64":
        # First byte of "MZ" header
        magic = [0x4D, 0x5F, 0xE0, 0xE9]
    else:
        print(M.error(f"kbase does not support the {arch_name} architecture"))
        return

    mappings = pwndbg.gdblib.vmmap.get()
    for mapping in mappings:
        # TODO: Check alignment

        if not mapping.vaddr & 0xFFFF000000000000:
            continue
        if not mapping.execute:
            continue
        try:
            b = pwndbg.gdblib.memory.byte(mapping.vaddr)
        except gdb.MemoryError:
            print(
                M.error(
                    f"Could not read memory at {mapping.vaddr:#x}. Kernel vmmap may be incorrect."
                )
            )
            continue
        if b in magic:
            base = mapping.vaddr
            if b != 0x4D:
                base -= 0x10000
            print(M.success(f"Found virtual base address: {base:#x}"))
            break
