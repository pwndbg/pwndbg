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
                # We need to match the relocation type from the file (which is an integer)
                # to our internal RelocationType enum (JUMP_SLOT, GLOB_DAT, IRELATIVE).
                #
                # pyelftools gives us the integer type via `rel['r_info_type']`.
                # We use `describe_reloc_type` to translate that integer into a human-readable string
                # like "R_X86_64_JUMP_SLOT".
                from elftools.elf.descriptions import describe_reloc_type

                reloc_type_name = describe_reloc_type(rel["r_info_type"], elf)

                # Now we check if this string contains one of the types we care about.
                # For example, if we are looking for JUMP_SLOT, we check if "JUMP_SLOT"
                # is inside "R_X86_64_JUMP_SLOT".

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
