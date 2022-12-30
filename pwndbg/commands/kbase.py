import argparse

import pwndbg.color.message as M
import pwndbg.commands
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
        # First opcode, seems to be consistent
        magic = 0x48
    elif arch_name == "aarch64":
        # First byte of "MZ" header
        magic = 0x4D
    else:
        print(M.error(f"kbase does not support the {arch_name} architecture"))
        return

    mappings = pwndbg.gdblib.vmmap.get()
    for mapping in mappings:
        # TODO: Check alignment
        # TODO: Check if the supervisor bit is set for aarch64
        if not mapping.execute:
            continue
        b = pwndbg.gdblib.memory.byte(mapping.vaddr)

        if b == magic:
            print(M.success(f"Found virtual base address: {mapping.vaddr:#x}"))
            break
