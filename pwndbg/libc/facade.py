from __future__ import annotations

import os
import re
from pathlib import Path

from elftools.elf.relocation import Relocation

import pwndbg.aglib.elf
import pwndbg.aglib.proc
import pwndbg.aglib.vmmap
import pwndbg.lib.cache

from . import glibc
from . import musl
from . import unknown
from .dispatch import LibcType
from .dispatch import LibcURLs
from .dispatch import LibcWrangler


def get_libc() -> LibcWrangler:
    if glibc._is_being_used():
        return glibc

    if musl._is_being_used():
        return musl

    assert unknown._is_being_used()
    return unknown


def which() -> LibcType:
    libc: LibcWrangler = get_libc()
    return libc.type()


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


# ======== Public API =========


def _is_being_used() -> bool:
    """
    Libc's need to implement this to identify whether they are
    the ones the debugee is using.

    If an implementation can't see any symbols and can't perform the check without
    them, it should return False.

    This is used to dispatch to the correct libc implementation, you shouldn't
    use this.

    If you want to check whether a specific libc implementation is active,
    do this: pwndbg.libc.get().type() == pwndbg.libc.LibcType.GLIBC .
    """
    ...


def has_symbols() -> bool:
    """
    Can we read out global variables and functions in the libc object file?
    """
    libc: LibcWrangler = get_libc()
    return libc.has_symbols()


def has_debug_info() -> bool:
    """
    Do we have debugging information like structure types?
    """
    libc: LibcWrangler = get_libc()
    return libc.has_debug_info()


def filepath() -> Path:
    """
    The filepath of the libc shared object.

    There may not be a backing file for this Path if we are remote debugging.
    This may have the same value as loader_filepath() for some libc's.
    """
    ...


def loader_filepath() -> Path:
    """
    The filepath of the ld shared object.

    There may not be a backing file for this Path if we are remote debugging.
    This may have the same value as filepath() for some libc's.
    """
    ...


def addr() -> int:
    """
    The start load address of the libc shared object file.

    May be the same as loader_addr() for some libc's.
    """
    yes = pwndbg.aglib.vmmap.named_region_start(str(filepath()))
    # We know filepath() will return an actual mapped objfile, so
    # `yes` must be non-None.
    assert yes is not None
    return yes


def loader_addr() -> int:
    """
    The start load address of the ld shared object file.

    May be the same as addr() for some libc's.
    """
    yes = pwndbg.aglib.vmmap.named_region_start(str(loader_filepath()))
    # We know loader_filepath will return an actual mapped objfile, so
    # `yes` must be non-None.
    assert yes is not None
    return yes


def section_by_name(section_name: str) -> tuple[int, int, bytes] | None:
    """
    Returns pwndbg.aglib.elf.section_by_name() for the libc shared object file.
    """
    assert pwndbg.aglib.proc.alive()

    return pwndbg.aglib.elf.section_by_name(str(filepath()), section_name, try_local_path=True)


def section_address_by_name(section_name: str) -> int:
    """
    Get the start load address of the section `section_name` in the libc shared
    object file.
    """
    # TODO: If we are debugging a remote process, this might not work if GDB cannot load the so file
    libc_path: str = str(filepath())
    for (
        address,
        size,
        candidate_section_name,
        module_name,
    ) in pwndbg.dbg.selected_inferior().module_section_locations():
        if section_name == candidate_section_name and module_name == libc_path:
            return address
    return 0


def relocations_by_section_name(section_name: str) -> tuple[Relocation, ...]:
    """
    Returns pwndbg.aglib.elf.relocations_by_section_name() for the libc shared object file.
    """
    assert pwndbg.aglib.proc.alive()

    return pwndbg.aglib.elf.relocations_by_section_name(
        str(filepath()), section_name, try_local_path=True
    )


def urls() -> LibcURLs:
    """
    Get useful URLs regarding this libc implementation.
    """
    libc: LibcWrangler = get_libc()
    return libc.urls()


# ======== End of Public API =========
