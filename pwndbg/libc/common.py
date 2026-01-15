from __future__ import annotations

from elftools.elf.relocation import Relocation

import pwndbg.aglib.elf
import pwndbg.aglib.proc
import pwndbg.lib.cache


@pwndbg.lib.cache.cache_until("start", "objfile")
def section_by_name(section_name: str, libc_filename: str) -> tuple[int, int, bytes] | None:
    assert pwndbg.aglib.proc.alive()

    return pwndbg.aglib.elf.section_by_name(libc_filename, section_name, try_local_path=True)


@pwndbg.lib.cache.cache_until("start", "objfile")
def section_address_by_name(section_name: str, libc_filename: str) -> int:
    """
    Find section address of libc by section name
    """
    # TODO: If we are debugging a remote process, this might not work if GDB cannot load the so file
    for (
        address,
        size,
        candidate_section_name,
        module_name,
    ) in pwndbg.dbg.selected_inferior().module_section_locations():
        if section_name == candidate_section_name and module_name == libc_filename:
            return address
    return 0


@pwndbg.lib.cache.cache_until("start", "objfile")
def relocations_by_section_name(section_name: str, libc_filename: str) -> tuple[Relocation, ...]:
    """
    Dump relocations of a section by section name of libc ELF file
    """
    assert pwndbg.aglib.proc.alive()

    return pwndbg.aglib.elf.relocations_by_section_name(
        libc_filename, section_name, try_local_path=True
    )
