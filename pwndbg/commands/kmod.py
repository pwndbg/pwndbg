"""
Displays information about loaded kernel modules. This command retrieves the list of kernel modules from the `modules` symbol
and displays information about each module. It can filter modules by a substring of their names if provided.
"""

from __future__ import annotations

import argparse
from enum import Enum
from typing import Tuple

from tabulate import tabulate

import pwndbg
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.aglib.kernel.macros import for_each_entry

parser = argparse.ArgumentParser(description="Displays the loaded Linux kernel modules.")
parser.add_argument(
    "module_name", nargs="?", type=str, help="A module name substring to filter for"
)


class mod_mem_type(Enum):
    # Calculate runtime memory footprint by summing sizes of MOD_TEXT, MOD_DATA, MOD_RODATA, MOD_RO_AFTER_INIT,
    # which excludes initialization sections that are freed after the module load. See `enum mod_mem_type` in kernel source.
    MOD_TEXT = 0
    MOD_DATA = 1
    MOD_RODATA = 2
    MOD_RO_AFTER_INIT = 3
    # MOD_INIT_TEXT,
    # MOD_INIT_DATA,
    # MOD_INIT_RODATA,
    MOD_MEM_NUM_TYPES = 4


# TODO: handle potential negative offsets when CONFIG_RANDSTRUCT=y
@pwndbg.lib.cache.cache_until("stop")
def module_name_offset():
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Cound not find modules"))
        return None
    module = pwndbg.aglib.memory.read_pointer_width(int(modules))
    for i in range(0x100):
        offset = i * pwndbg.aglib.arch.ptrsize
        try:
            bs = pwndbg.aglib.memory.string(module + offset).decode("ascii")
            if len(bs) < 2:
                continue
            return offset
        except Exception:
            pass
    print(M.warn("Could not find module->name"))
    return None


@pwndbg.lib.cache.cache_until("stop")
def module_mem_offset() -> Tuple[int | None, int | None, int | None]:
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Cound not find modules"))
        return None, None, None
    module = pwndbg.aglib.memory.read_pointer_width(int(modules))
    for i in range(0x100):
        offset = i * pwndbg.aglib.arch.ptrsize
        min_size = 0x10
        if pwndbg.aglib.kernel.krelease() >= (6, 13):
            min_size += 0x8
        for module_memory_size in (
            min_size,
            min_size + 0x38,
        ):
            found = True
            for mem_type in range(mod_mem_type.MOD_MEM_NUM_TYPES.value - 1):
                mem_ptr = module + offset + mem_type * module_memory_size
                if pwndbg.aglib.memory.peek(mem_ptr) is None:
                    found = False
                    break
                base = pwndbg.aglib.memory.read_pointer_width(mem_ptr)
                if base == 0 or ((base & 0xFFF) != 0):
                    found = False
                    break
                size_offset = pwndbg.aglib.arch.ptrsize
                if pwndbg.aglib.kernel.krelease() >= (6, 13):
                    size_offset += pwndbg.aglib.arch.ptrsize + 4
                size = pwndbg.aglib.memory.u32(mem_ptr + size_offset)
                if not 0 < size < 0x100000:
                    found = False
                    break
            if found:
                return offset, module_memory_size, size_offset
    print(M.warn("Cound not find module->mem"))
    return None, None, None


@pwndbg.lib.cache.cache_until("stop")
def module_layout_offset() -> Tuple[int | None, int | None]:
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Cound not find modules"))
        return None, None
    module = pwndbg.aglib.memory.read_pointer_width(int(modules))
    for i in range(0x100):
        offset = i * pwndbg.aglib.arch.ptrsize
        ptr = module + offset + pwndbg.aglib.arch.ptrsize
        if pwndbg.aglib.memory.peek(ptr) is None:
            continue
        base = pwndbg.aglib.memory.read_pointer_width(ptr)
        if base == 0 or ((base & 0xFFF) != 0):
            continue
        valid = True
        for i in range(4):
            size = pwndbg.aglib.memory.u32(ptr + 4 * i)
            if not 0 < size < 0x100000:
                valid = False
                break
        if valid:
            return offset, offset + pwndbg.aglib.arch.ptrsize
    print(M.warn("Cound not find module->init_layout"))
    return None, None


@pwndbg.lib.cache.cache_until("stop")
def module_kallsyms_offset():
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Cound not find modules"))
        return None, None
    module = pwndbg.aglib.memory.read_pointer_width(int(modules))
    for i in range(0x100):
        offset = i * pwndbg.aglib.arch.ptrsize
        ptr = module + offset
        if pwndbg.aglib.memory.peek(ptr) is None:
            continue
        kallsyms = pwndbg.aglib.memory.read_pointer_width(ptr)
        if pwndbg.aglib.memory.peek(kallsyms) is None or kallsyms == 0:
            continue
        symtab = pwndbg.aglib.memory.read_pointer_width(kallsyms)
        if pwndbg.aglib.memory.peek(symtab) is None:
            continue
        num_symtab = pwndbg.aglib.memory.read_pointer_width(
            kallsyms + pwndbg.aglib.arch.ptrsize * 1
        )
        if pwndbg.aglib.memory.peek(num_symtab) is not None or num_symtab == 0:
            continue
        strtab = pwndbg.aglib.memory.read_pointer_width(kallsyms + pwndbg.aglib.arch.ptrsize * 2)
        if pwndbg.aglib.memory.peek(strtab) is None:
            continue
        if pwndbg.aglib.kernel.krelease() >= (5, 2):
            typetab = pwndbg.aglib.memory.read_pointer_width(
                kallsyms + pwndbg.aglib.arch.ptrsize * 3
            )
            if pwndbg.aglib.memory.peek(typetab) is None:
                continue
        return offset
    print(M.warn("Could not find module->kallsyms"))
    return None


@pwndbg.lib.cache.cache_until("stop")
def get_module_list_with_typeinfo() -> Tuple[pwndbg.dbg_mod.Value, ...]:
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Cound not find modules"))
        return ()
    result = []
    head = pwndbg.aglib.memory.get_typed_pointer_value("struct list_head", modules)
    for module in for_each_entry(head, "struct module", "list"):
        result.append(module)
    # each entry if pointing to hte start of the module
    return tuple(result)


@pwndbg.lib.cache.cache_until("stop")
def get_module_list() -> Tuple[int, ...]:
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Cound not find modules"))
        return ()
    modules = int(modules)
    result = []
    cur = pwndbg.aglib.memory.read_pointer_width(int(modules))
    while cur != modules:
        result.append(cur)
        cur = pwndbg.aglib.memory.read_pointer_width(cur)
    # each entry is pointing to the module->next
    return tuple(result)


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugSymbols
def kmod(module_name=None) -> None:
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
    if pwndbg.aglib.typeinfo.load("struct module") is not None:
        # Iterate through the linked list of modules using for_each_entry
        for module in get_module_list_with_typeinfo():
            name = pwndbg.aglib.memory.string(int(module["name"].address)).decode(
                "utf-8", errors="ignore"
            )
            addr, size = None, None
            if pwndbg.aglib.kernel.krelease() >= (6, 4):
                addr = int(module["mem"][0]["base"])
                size = sum(
                    int(module["mem"][i]["size"])
                    for i in range(mod_mem_type.MOD_MEM_NUM_TYPES.value)
                )
            else:
                addr = int(module["init_layout"]["addr"])
                size = module["init_layout"]["size"]
            uses = int(module["refcnt"]["counter"]) - 1

            # If module_name is provided, filter modules by name substring
            if not module_name or module_name in name:
                table.append([f"{addr:#x}", name, size, uses])
    else:
        cur = pwndbg.aglib.memory.read_pointer_width(int(modules_head))
        name_offset = module_name_offset()
        # TODO: handle when kallsyms doesnt exist
        for cur in get_module_list():
            name = pwndbg.aglib.memory.string(cur + name_offset).decode()
            if pwndbg.aglib.kernel.krelease() >= (6, 4):
                mem_offset, module_memory_size, size_offset = module_mem_offset()
                addr = pwndbg.aglib.memory.read_pointer_width(cur + mem_offset)
                size = 0
                for i in range(mod_mem_type.MOD_MEM_NUM_TYPES.value):
                    ptr = cur + mem_offset + module_memory_size * i
                    size += pwndbg.aglib.memory.u32(ptr + size_offset)
            else:
                addr_offset, size_offset = module_layout_offset()
                addr = pwndbg.aglib.memory.read_pointer_width(cur + addr_offset)
                size = pwndbg.aglib.memory.u32(cur + size_offset)

            if not module_name or module_name in name:
                table.append([f"{addr:#x}", name, size, "-"])
    print(tabulate(table, headers=headers, tablefmt="simple"))
