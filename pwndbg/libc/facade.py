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

# Order is important.
_libc_implementations: tuple[LibcWrangler, ...] = (
    glibc, musl, unknown
)

def get_libc() -> LibcWrangler:
    for impl in _libc_implementations:
        if impl._is_being_used():
            return impl

    # This won't be reached because unknown will be returned in the loop
    # but okay.
    return unknown

def which() -> LibcType:
    libc: LibcWrangler = get_libc()
    return libc.type()


class LibcNotFound(Exception):
    pass

libc_regex = re.compile(r"^libc6?[-_\.]")
ld_regex = re.compile(r"ld.*\.so(?:\.[0-9]+)?")


@pwndbg.lib.cache.cache_until("start", "objfile")
def _libc_and_ld_filepath() -> tuple[Path | None, Path | None]:
    """
    The filepath of the libc and ld shared objects.

    There may not be a backing file for these Paths if we are remote debugging.
    The two paths may have the same value for some libc's (e.g. musl).
    """
    inf = pwndbg.dbg.selected_inferior()
    assert inf.alive()

    seen: set[str] = set()

    # Skip the executable
    maybe_main_module = inf.main_module_name()
    if maybe_main_module is not None:
        seen.add(maybe_main_module)

    all_sections: list[tuple[int, int, str, str]] = inf.module_section_locations()
    all_module_names: list[str] = [sec[3] for sec in all_sections]

    exact_libc_basename_matches: list[str] = [
        # glibc
        "libc.so.6",
        # musl and bionic (android)
        "libc.so"
    ]
    exact_ld_basename_matches: list[str] = [
        # x86_64 glibc
        "ld-linux-x86-64.so.2",
        # Common in CTF's
        "ld-linux.so",
        # x86_64 musl ld (shows up on fedora)
        "ld-musl-x86_64.so.1",
    ]

    possible_libc_paths: list[str] = []
    possible_ld_paths: list[str] = []
    certain_libc_path: str | None = None
    certain_ld_path: str | None = None

    for path in all_module_names:
        if path in seen:
            continue
        seen.add(path)

        basename = os.path.basename(
            # Strip "target:" prefix used for remote debugging
            path[7:] if path.startswith("target:") else path
        )

        # Check for libc
        if certain_libc_path is not None:
            if basename in exact_libc_basename_matches:
                # This is exceedingly likely to be the correct module.
                certain_libc_path = path
            elif libc_regex.search(basename) is not None:
                # Maybe the user loaded the libc with LD_PRELOAD.
                # Some common libc names: libc-2.36.so, libc6_2.36-0ubuntu4_amd64.so, libc.so
                possible_libc_paths.append(path)

        # Check for ld
        if certain_ld_path is not None:
            if basename in exact_ld_basename_matches:
                # This is exceedingly likely to be the correct module.
                certain_ld_path = path
            elif ld_regex.search(basename) is not None:
                possible_ld_paths.append(path)

    def verify_libc_path(path: str) -> tuple[bool, LibcType]:
        for impl in _libc_implementations:
            if impl.verify_libc_candidate(path):
                # Someone claims that this makes sense!
                return True, impl.type()
        return False, LibcType.UNKNOWN

    # Let's see if any libc implementation verifies any of the
    # candidate paths we found.
    verified_libc_path: str | None = None
    verified_ld_path: str | None = None

    if certain_libc_path is not None:
        ok, approver = verify_libc_path(certain_libc_path)
        if ok:
            verified_libc_path = certain_libc_path

    if not verified_libc_path:
        for cand in possible_libc_paths:
            ok, approver = verify_libc_path(cand)
            if ok:
                verified_libc_path = cand
                break

    def verify_ld_path(path: str) -> tuple[bool, LibcType]:
        for impl in _libc_implementations:
            if impl.verify_ld_candidate(path):
                # Someone claims that this makes sense!
                return True, impl.type()
        return False, LibcType.UNKNOWN

    if certain_ld_path is not None:
        ok, approver = verify_ld_path(certain_ld_path)
        if ok:
            verified_ld_path = certain_ld_path

    if not verified_ld_path:
        for cand in possible_ld_paths:
            ok, approver = verify_ld_path(cand)
            if ok:
                verified_ld_path = cand
                break

    if verified_libc_path is not None and verified_ld_path is not None:
        # We are happy.
        return Path(verified_libc_path), Path(verified_ld_path)

    # think about this more

    # TODO: This might fail if user use LD_PRELOAD to load libc with a weird name or there are multiple shared libraries match the pattern.
    # (But do we really need to support this case? Maybe we can wait until users really need it :P.)
    if possible_libc_paths:
        return possible_libc_paths[0]  # just return the first match for now :)
    return None


# ======== Public API =========


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
