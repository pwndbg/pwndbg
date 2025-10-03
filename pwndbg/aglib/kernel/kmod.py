from __future__ import annotations

from enum import Enum
from typing import List
from typing import Tuple

import pwndbg
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.aglib.kernel.macros import for_each_entry


class mod_mem_type(Enum):
    # Calculate runtime memory footprint by summing sizes of MOD_TEXT, MOD_DATA, MOD_RODATA, MOD_RO_AFTER_INIT,
    # which excludes initialization sections that are freed after the module load. See `enum mod_mem_type` in kernel source.
    MOD_TEXT = 0
    MOD_DATA = 1
    MOD_RODATA = 2
    MOD_RO_AFTER_INIT = 3  # might be empty
    # MOD_INIT_TEXT,
    # MOD_INIT_DATA,
    # MOD_INIT_RODATA,
    MOD_MEM_NUM_TYPES = 4


# TODO: handle potential negative offsets when CONFIG_RANDSTRUCT=y
@pwndbg.lib.cache.cache_until("stop")
def module_name_offset():
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Could not find modules"))
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
        print(M.warn("Could not find modules"))
        return None, None, None
    module = pwndbg.aglib.memory.read_pointer_width(int(modules))
    for i in range(0x100):
        offset = i * pwndbg.aglib.arch.ptrsize
        min_size = 0x10
        if (6, 13) <= pwndbg.aglib.kernel.krelease() < (6, 15):
            min_size += 0x8
        for module_memory_size in (
            min_size,
            min_size + 0x38,
        ):
            found = True
            for mem_type in range(mod_mem_type.MOD_RO_AFTER_INIT.value):
                mem_ptr = module + offset + mem_type * module_memory_size
                if pwndbg.aglib.memory.peek(mem_ptr) is None:
                    found = False
                    break
                base = pwndbg.aglib.memory.read_pointer_width(mem_ptr)
                if base == 0 or ((base & 0xFFF) != 0):
                    found = False
                    break
                size_offset = pwndbg.aglib.arch.ptrsize
                if (6, 13) <= pwndbg.aglib.kernel.krelease() < (6, 15):
                    # https://elixir.bootlin.com/linux/v6.13/source/include/linux/module.h#L368
                    # additional fields were added
                    size_offset += pwndbg.aglib.arch.ptrsize + 4
                elif (6, 15) <= pwndbg.aglib.kernel.krelease():
                    size_offset += 4
                size = pwndbg.aglib.memory.u32(mem_ptr + size_offset)
                if not 0 < size < 0x100000:
                    found = False
                    break
            if found:
                return offset, module_memory_size, size_offset
    print(M.warn("Could not find module->mem"))
    return None, None, None


@pwndbg.lib.cache.cache_until("stop")
def module_layout_offset() -> Tuple[int | None, int | None]:
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Could not find modules"))
        return None, None
    module = pwndbg.aglib.memory.read_pointer_width(int(modules))
    for i in range(0x100):  # enough to search through the struct
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
    print(M.warn("Could not find module->init_layout"))
    return None, None


@pwndbg.lib.cache.cache_until("stop")
def module_kallsyms_offset():
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Could not find modules"))
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
        num_symtab = pwndbg.aglib.memory.read_pointer_width(kallsyms + pwndbg.aglib.arch.ptrsize)
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
def module_list_with_typeinfo() -> Tuple[pwndbg.dbg_mod.Value, ...]:
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Could not find modules"))
        return ()
    result = []
    head = pwndbg.aglib.memory.get_typed_pointer_value("struct list_head", modules)
    for module in for_each_entry(head, "struct module", "list"):
        result.append(module)
    # each entry if pointing to hte start of the module
    return tuple(result)


@pwndbg.lib.cache.cache_until("stop")
def module_list() -> Tuple[int, ...]:
    modules = pwndbg.aglib.kernel.modules()
    if modules is None:
        print(M.warn("Could not find modules"))
        return ()
    modules = int(modules)
    result = []
    cur = pwndbg.aglib.memory.read_pointer_width(modules)
    while cur != modules:
        result.append(cur)
        cur = pwndbg.aglib.memory.read_pointer_width(cur)
    # each entry is pointing to the module->next
    return tuple(result)


def parse_module_kallsyms(kallsyms: int) -> List[Tuple[str, int, str]]:
    is_64bit = pwndbg.aglib.arch.ptrsize == 8
    sizeof_symtab_entry = 24 if is_64bit else 16
    result = []
    symtab = pwndbg.aglib.memory.read_pointer_width(kallsyms)
    num_symtab = pwndbg.aglib.memory.read_pointer_width(kallsyms + pwndbg.aglib.arch.ptrsize)
    strtab = pwndbg.aglib.memory.read_pointer_width(kallsyms + pwndbg.aglib.arch.ptrsize * 2)
    typetab = None
    if pwndbg.aglib.kernel.krelease() >= (5, 2):
        typetab = pwndbg.aglib.memory.read_pointer_width(kallsyms + pwndbg.aglib.arch.ptrsize * 3)
    strtab_offset = 0
    for i in range(num_symtab):
        sym_name = pwndbg.aglib.memory.string(strtab + strtab_offset).decode("utf-8")
        strtab_offset += len(sym_name) + 1
        if len(sym_name) == 0:
            continue
        sym_addr = pwndbg.aglib.memory.read_pointer_width(
            int(symtab) + sizeof_symtab_entry * i + pwndbg.aglib.arch.ptrsize
        )
        sym_type = None
        if pwndbg.aglib.kernel.krelease() >= (5, 2):
            sym_type = chr(pwndbg.aglib.memory.u8(typetab + i))
        else:
            sym_type = chr(
                pwndbg.aglib.memory.u8(symtab + sizeof_symtab_entry * i + 16 if is_64bit else 8)
            )
        result.append((sym_name, sym_addr, sym_type))
    return result


def all_modules_kallsyms() -> List[Tuple[str, int, str]]:
    result = []
    if pwndbg.aglib.typeinfo.load("struct module") is not None:
        for module in module_list_with_typeinfo():
            if module.type.has_field("kallsyms"):
                kallsyms = int(module["kallsyms"])
                result += parse_module_kallsyms(kallsyms)
    elif module_kallsyms_offset() is not None:
        for module in module_list():
            kallsyms = pwndbg.aglib.memory.read_pointer_width(module + module_kallsyms_offset())
            result += parse_module_kallsyms(kallsyms)
    return result
