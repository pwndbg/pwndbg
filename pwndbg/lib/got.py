from __future__ import annotations

from enum import Enum

from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerNeedSection
from elftools.elf.gnuversions import GNUVerSymSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


class RelocationType(Enum):
    # For x86_64, some details about these flag can be found in 4.4.1 Relocation Types in https://www.intel.com/content/dam/develop/external/us/en/documents/mpx-linux64-abi.pdf
    # The definitions of these flags can be found in this file: https://elixir.bootlin.com/glibc/glibc-2.37/source/elf/elf.h
    JUMP_SLOT = 1  # e.g.: R_X86_64_JUMP_SLOT
    GLOB_DAT = 2  # e.g.: R_X86_64_GLOB_DAT
    IRELATIVE = 3  # e.g.: R_X86_64_IRELATIVE


def get_got_entry(local_path: str) -> dict[RelocationType, list[dict[str, int | str]]]:
    entries: dict[RelocationType, list[dict[str, int | str]]] = {
        category: [] for category in RelocationType
    }

    with open(local_path, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue

            for rel in section.iter_relocations():
                # Get the symbol table and look up the symbol for this relocation
                symbol_table = elf.get_section(section["sh_link"])
                assert isinstance(symbol_table, SymbolTableSection)
                symbol = symbol_table.get_symbol(rel["r_info_sym"])
                symbol_name = symbol.name

                # Try to get the symbol version (e.g., @GLIBC_2.2.5)
                symbol_version = ""
                try:
                    # Get the version section if it exists
                    versym_section = elf.get_section_by_name(".gnu.version")
                    verneed_section = elf.get_section_by_name(".gnu.version_r")
                    assert isinstance(versym_section, GNUVerSymSection)
                    assert isinstance(verneed_section, GNUVerNeedSection)

                    if (
                        versym_section
                        and verneed_section
                        and rel["r_info_sym"] < versym_section.num_symbols()
                    ):
                        # Get the version index for this symbol
                        version_index = versym_section.get_symbol(rel["r_info_sym"])["ndx"]

                        # Version index 0 and 1 are special (local/global)
                        if version_index > 1:
                            # Iterate through version requirements to find the matching version
                            # iter_versions() returns tuples of (verneed, vernaux_iter)
                            for _, vernaux_iter in verneed_section.iter_versions():
                                for vernaux in vernaux_iter:
                                    if vernaux["vna_other"] == version_index:
                                        symbol_version = f"@{vernaux.name}"
                                        break
                                if symbol_version:
                                    break
                except Exception:
                    # If we can't get version info, just use the base name
                    pass

                # Combine symbol name with version if available
                full_symbol_name = symbol_name + symbol_version

                # We need to match the relocation type from the file (which is an integer)
                # to our internal RelocationType enum (JUMP_SLOT, GLOB_DAT, IRELATIVE).
                #
                # pyelftools gives us the integer type via `rel['r_info_type']`.
                # We use `describe_reloc_type` to translate that integer into a human-readable string
                # like "R_X86_64_JUMP_SLOT".
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
                                "name": full_symbol_name,
                                "addend": rel.entry.get("r_addend", 0),
                            }
                        )
    return entries
