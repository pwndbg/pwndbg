from __future__ import annotations

import os
import re
from pathlib import Path

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


libc_regex = re.compile(r"^libc6?[-_\.]")

@pwndbg.lib.cache.cache_until("start", "objfile")
def _libc_and_ld_filepath() -> Path | None:
    """
    The filepath of the libc shared object.

    There may not be a backing file for this Path if we are remote debugging.
    This may have the same value as loader_filepath() for some libc's.
    """
    possible_libc_path: list[str] = []
    inf = pwndbg.dbg.selected_inferior()

    seen: set[str] = set()

    # Skip the executable
    maybe_main_module = inf.main_module_name()
    if maybe_main_module is not None:
        seen.add(maybe_main_module)

    all_sections: list[tuple[int, int, str, str]] = inf.module_section_locations()
    all_module_names: list[str] = [sec[3] for sec in all_sections]

    for path in all_module_names:
        if path in seen:
            continue
        seen.add(path)

        basename = os.path.basename(
            # Strip "target:" prefix used for remote debugging
            path[7:] if path.startswith("target:") else path
        )

        # If we find an exact match on these, we return it without caring about anything else.
        # glibc will be libc.so.6, musl and bionic are libc.so
        if basename == "libc.so.6" or basename == "libc.so":
            return Path(path)

        if libc_regex.search(basename) is not None:
            # Maybe the user loaded the libc with LD_PRELOAD.
            # Some common libc names: libc-2.36.so, libc6_2.36-0ubuntu4_amd64.so, libc.so
            possible_libc_path.append(path)
            
    
    for _, _, _, module_name in all_sections:
        if module_name in seen:
            continue
        seen.add(module_name)

        path = module_name
        basename = os.path.basename(
            # Strip "target:" prefix used for remote debugging
            path[7:] if path.startswith("target:") else path
        )

        if basename == "libc.so.6":
            # The default filename of libc should be libc.so.6, so if we found it, we just return it directly.
            return Path(path)
        elif re.search(r"^libc6?[-_\.]", basename):
            # Maybe user loaded the libc with LD_PRELOAD.
            # Some common libc names: libc-2.36.so, libc6_2.36-0ubuntu4_amd64.so, libc.so
            possible_libc_path.append(
                path
            )  # We don't return it, maybe there is a libc.so.6 and this match is just a false positive.
    # TODO: This might fail if user use LD_PRELOAD to load libc with a weird name or there are multiple shared libraries match the pattern.
    # (But do we really need to support this case? Maybe we can wait until users really need it :P.)
    if possible_libc_path:
        return possible_libc_path[0]  # just return the first match for now :)
    return None

