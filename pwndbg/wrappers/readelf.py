from __future__ import annotations

from enum import Enum
from typing import Dict
from typing import List

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import pwndbg.wrappers

cmd_name = "readelf"


class RelocationType(Enum):
    # For x86_64, some details about these flag can be found in 4.4.1 Relocation Types in https://www.intel.com/content/dam/develop/external/us/en/documents/mpx-linux64-abi.pdf
    # The definitions of these flags can be found in this file: https://elixir.bootlin.com/glibc/glibc-2.37/source/elf/elf.h
    JUMP_SLOT = 1  # e.g.: R_X86_64_JUMP_SLOT
    GLOB_DAT = 2  # e.g.: R_X86_64_GLOB_DAT
    IRELATIVE = 3  # e.g.: R_X86_64_IRELATIVE


def get_got_entry(local_path: str) -> Dict[RelocationType, List[Dict[str, int | str]]]:
    entries: Dict[RelocationType, List[Dict[str, int | str]]] = {
        category: [] for category in RelocationType
    }

    with open(local_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            for rel in section.iter_relocations():
                # Check if the relocation type matches one of our interesting types
                # The relocation type is an integer, but we can look up its name
                # or just match the name if we know the mapping.
                # pyelftools provides `_RELOC_TYPE_ARCH` but it's private.
                # However, `rel['r_info_type']` gives the integer type.
                # We can use `describe_reloc_type` to get the string name if needed,
                # or just use the integer if we map it correctly.
                # But `RelocationType` enum values are integers (1, 2, 3).
                # These are NOT the ELF relocation type values.
                # They are just internal IDs for Pwndbg.
                # We need to match the ELF relocation type name.

                # rel.entry.r_info_type is the integer type.
                # We can get the symbol table to look up the symbol name.
                symbol_table = elf.get_section(section["sh_link"])
                symbol = symbol_table.get_symbol(rel["r_info_sym"])
                symbol_name = symbol.name

                # We need the relocation type name to match against RelocationType enum names
                # (JUMP_SLOT, GLOB_DAT, IRELATIVE)
                # We can use `pwndbg.aglib.arch` to know the arch, but `local_path` might be foreign.
                # `ELFFile` knows the arch: `elf.get_machine_arch()`

                # Let's use `describe_reloc_type` from elftools to get the name
                from elftools.elf.descriptions import describe_reloc_type

                reloc_type_name = describe_reloc_type(rel["r_info_type"], elf)

                # Now check if this type name contains our interesting types
                # The original code checked: `if c.name in category`
                # where `category` was the string from readelf (e.g. R_X86_64_JUMP_SLOT)
                # and `c.name` is JUMP_SLOT.

                for c in RelocationType:
                    if c.name in reloc_type_name:
                        entries[c].append(
                            {
                                "offset": rel["r_offset"],
                                "info": rel["r_info"],
                                "type": reloc_type_name,
                                "value": symbol["st_value"],
                                "name": symbol_name,
                                "addend": rel.entry.get("r_addend", 0),
                            }
                        )
    return entries
