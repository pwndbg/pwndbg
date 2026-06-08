"""
Displays information about loaded kernel modules. This command retrieves the list of kernel modules from the `modules` symbol
and displays information about each module. It can filter modules by a substring of their names if provided.
"""

from __future__ import annotations

import argparse

from tabulate import tabulate

import pwndbg
import pwndbg.aglib.kernel.kmod
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.commands
from pwndbg.color import message

parser = argparse.ArgumentParser(description="Displays the loaded Linux kernel modules.")
parser.add_argument(
    "module_name", nargs="?", type=str, help="A module name substring to filter for"
)
parser.add_argument("-l", "--load", dest="path", type=str, help="the path of the module to load")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
def kmod(module_name: str | None = None, path: str | None = None) -> None:
    # Look up the address of the `modules` symbol, containing the head of the linked list of kernel modules
    modules_head = pwndbg.aglib.kernel.modules()
    if modules_head is None:
        print(
            "The modules symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return

    print(f"Kernel modules address found at {modules_head:#x}.\n")

    table = []
    headers = ["Address", "Name", "Size", "Used by"]
    krelease = pwndbg.aglib.kernel.krelease()
    if pwndbg.aglib.typeinfo.load("struct module") is not None:
        # Iterate through the linked list of modules using for_each_entry
        for module in pwndbg.aglib.kernel.kmod.module_list_with_typeinfo():
            name_addr = module["name"].address
            assert name_addr
            name = pwndbg.aglib.memory.string(int(name_addr)).decode("utf-8", errors="ignore")
            if not krelease or krelease >= (6, 4):
                addr = int(module["mem"][0]["base"])
                size = sum(
                    int(module["mem"][i]["size"])
                    for i in range(pwndbg.aglib.kernel.kmod.mod_mem_type.MOD_MEM_NUM_TYPES.value)
                )
            else:
                addr = int(module["core_layout"]["base"])
                size = int(module["core_layout"]["size"])
            uses = int(module["refcnt"]["counter"]) - 1

            # If module_name is provided, filter modules by name substring
            if not module_name or module_name in name:
                table.append([f"{addr:#x}", name, size, uses])
    else:
        cur = pwndbg.aglib.memory.read_pointer_width(modules_head)
        name_offset = pwndbg.aglib.kernel.kmod.module_name_offset()
        if not name_offset:
            print(message.warn("module->name offset not found"))
            return
        for cur in pwndbg.aglib.kernel.kmod.module_list():
            name = pwndbg.aglib.memory.string(cur + name_offset).decode()
            if not krelease or krelease >= (6, 4):
                mem_offset, module_memory_size, size_offset = (
                    pwndbg.aglib.kernel.kmod.module_mem_offset()
                )
                if mem_offset is None or module_memory_size is None or size_offset is None:
                    continue
                addr = pwndbg.aglib.memory.read_pointer_width(cur + mem_offset)
                size = 0
                for i in range(pwndbg.aglib.kernel.kmod.mod_mem_type.MOD_MEM_NUM_TYPES.value):
                    ptr = cur + mem_offset + module_memory_size * i
                    size += pwndbg.aglib.memory.u32(ptr + size_offset)
            else:
                addr_offset, size_offset = pwndbg.aglib.kernel.kmod.module_layout_offset()
                if addr_offset is None or size_offset is None:
                    continue
                addr = pwndbg.aglib.memory.read_pointer_width(cur + addr_offset)
                size = pwndbg.aglib.memory.u32(cur + size_offset)

            if not module_name or module_name in name:
                table.append([f"{addr:#x}", name, size, "-"])
    if path is not None:
        if len(table) == 1:
            addr = table[0][0]
            pwndbg.dbg.selected_inferior().add_symbol_file(path, addr)
            # FIXME: Reintroduce rizin/radare2 support here.
            # if pwndbg.config.decompiler == "radare2":
            #     pwndbg.radare2.r2cmd(["o", path, addr])
            # elif pwndbg.config.decompiler == "rizin":
            #     pwndbg.rizin.rzcmd(["o", path, addr])
        elif len(table) > 1:
            print(message.warn("Multiple modules detected with the given filter"))
        else:
            print(message.warn("No modules detected with the given filter."))
        return

    print(tabulate(table, headers=headers, tablefmt="simple"))
