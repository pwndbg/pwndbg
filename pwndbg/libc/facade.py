"""
Implements the libc API.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from elftools.elf.relocation import Relocation

import pwndbg.aglib.elf
import pwndbg.aglib.proc
import pwndbg.aglib.vmmap
import pwndbg.lib.cache
import pwndbg.lib.path

from . import glibc
from . import musl
from . import unknown
from . import util
from .dispatch import LibcProvider
from .dispatch import LibcType
from .dispatch import LibcURLs

# Order is important.
_libc_implementations: tuple[LibcProvider, ...] = (glibc, musl, unknown)


class LibcNotFound(Exception):
    pass


def __check_candidates(
    libc_candidates: list[str], ld_candidates: list[str]
) -> tuple[str | None, str | None, LibcProvider | None]:
    """
    Queries the libc implementations on if any of them claim any libc and ld mappings.

    Returns:
        A tuple (claimed libc mapping, claimed ld mapping, claiming implementation). If noone claimed anything,
        "claiming implementation" will be None. It is possible that exactly one of "claimed libc mapping"
        and "claimed ld mapping" is None.
    """

    def verify_libc_path(path: str) -> tuple[bool, LibcProvider]:
        for impl in _libc_implementations:
            if impl.verify_libc_candidate(path):
                # Someone claims that this makes sense!
                return True, impl
        return False, unknown

    def verify_ld_path(path: str) -> tuple[bool, LibcProvider]:
        for impl in _libc_implementations:
            if impl.verify_ld_candidate(path):
                # Someone claims that this makes sense!
                return True, impl
        return False, unknown

    verified_libc_path: str | None = None
    verified_ld_path: str | None = None
    verified_libc_impl: LibcProvider | None = None

    # See if any libc implementation claims one of the candidate libc mappings.
    for cand in libc_candidates:
        ok, approver = verify_libc_path(cand)
        if ok:
            verified_libc_path = cand
            verified_libc_impl = approver
            break

    # See if any libc implementation claims one of the candidate ld mappings.
    for cand in ld_candidates:
        ok, approver = verify_ld_path(cand)
        if ok:
            # Is there a conflict with the libc verifier?
            if verified_libc_impl is not None and verified_libc_impl.type() != approver.type():
                assert verified_libc_path is not None
                raise LibcNotFound(
                    f"Conflict: {verified_libc_path} is a {verified_libc_impl.type().value} mapping"
                    f" while {cand} is a {approver.type()} mapping."
                )

            verified_ld_path = cand
            verified_libc_impl = approver
            break

    return verified_libc_path, verified_ld_path, verified_libc_impl


libc_regex = re.compile(r"^libc6?[-_\.]")
ld_regex = re.compile(r"ld.*\.so(?:\.[0-9]+)?")

# TODO: A potentially significant performance optimization could be, if we have a LibcWrangler
# which is not "unknown", we don't need to clear the cache on objfile events (but probably still
# should on start events).


@pwndbg.lib.cache.cache_until("start", "objfile")
def __get_libc() -> tuple[Path, Path, LibcProvider]:
    """
    Find the active libc implementation and the associated libc and ld mappings.

    The process must be alive when this is called.

    If the program is statically linked, will return the main executable module's
    Path for the libc and ld path, and still try to infer the libc implementation.

    If no libc verifies anything, but there is at least one libc OR ld candidate
    mapping, it/they will be returned along with the "unknown" libc implementation.

    Returns:
        A tuple (libc mapping path, ld mapping path, libc implementation). Both of
            the returned Path's are resolved (absolute, followed symlinks).

    Raises:
        LibcNotFound: If the binary is dynamically linked and we couldn't find
            any candidate mappings.
    """
    # This function works by finding likely libc and ld mappings based on their
    # path names, and quering the libc implementations on them to see if any
    # claim the mapping as theirs. If noone claims the mappings, we return the
    # "unknown" libc implementation with the likely mappings.

    inf = pwndbg.dbg.selected_inferior()
    assert inf.alive()

    seen: set[str] = set()

    # Skip the executable
    maybe_main_module = inf.main_module_name()
    if maybe_main_module is not None:
        maybe_main_module = pwndbg.lib.path.clean_path(maybe_main_module)
        seen.add(maybe_main_module)

    all_sections: list[tuple[int, int, str, str]] = inf.module_section_locations()
    all_module_names: list[str] = [sec[3] for sec in all_sections]

    exact_libc_basename_matches: list[str] = [
        # glibc
        "libc.so.6",
        # musl and bionic (android)
        "libc.so",
    ]
    exact_ld_basename_matches: list[str] = [
        # x86_64 glibc
        "ld-linux-x86-64.so.2",
        # Common in CTF's
        "ld-linux.so",
        # x86_64 musl ld
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
            path.removeprefix("target:")
        )

        # Get absolute path and resolve symlinks if it seems plausible.
        # See #3641.
        path = pwndbg.lib.path.clean_path(path)

        # Check for libc
        if certain_libc_path is None and basename in exact_libc_basename_matches:
            # This is exceedingly likely to be the correct module.
            certain_libc_path = path
        elif libc_regex.search(basename) is not None:
            # Maybe the user loaded the libc with LD_PRELOAD.
            # Some common libc names: libc-2.36.so, libc6_2.36-0ubuntu4_amd64.so, libc.so
            possible_libc_paths.append(path)

        # Check for ld
        if certain_ld_path is None and basename in exact_ld_basename_matches:
            # This is exceedingly likely to be the correct module.
            certain_ld_path = path
        elif ld_regex.search(basename) is not None:
            possible_ld_paths.append(path)

    # Put the likeliest paths in the front. But also check the other ones
    # in case something else gets verified.
    # Though this would be extremely weird. Maybe we shouldn't allow it?
    if certain_libc_path:
        possible_libc_paths = [certain_libc_path] + possible_libc_paths
    if certain_ld_path:
        possible_ld_paths = [certain_ld_path] + possible_ld_paths

    # If we are statically linked, pass in the main module as it will contain
    # some libc stuff inside it (only the stuff that is actaully used).
    if not pwndbg.dbg.selected_inferior().is_dynamically_linked():
        # maybe_main_module should be non-None if the process is alive.
        assert maybe_main_module is not None
        possible_libc_paths = [maybe_main_module]
        possible_ld_paths = [maybe_main_module]

    # Let's see if any libc implementation verifies any of the
    # candidate paths we found.
    verified: tuple[str | None, str | None, LibcProvider | None] = __check_candidates(
        possible_libc_paths, possible_ld_paths
    )
    verified_libc_path, verified_ld_path, verified_libc_impl = verified

    if verified_libc_impl is not None:
        # Someone approved something!
        if verified_libc_path is not None and verified_ld_path is not None:
            return (Path(verified_libc_path), Path(verified_ld_path), verified_libc_impl)
        if verified_libc_path is not None:
            # We didn't get an approved ld path.
            # Lets ask the libc if it wants us to return the same path for the ld as for the libc,
            # or try to get an ld candidate.
            if not verified_libc_impl.libc_same_as_ld() and possible_ld_paths:
                ld_ret = possible_ld_paths[0]
            else:
                ld_ret = verified_libc_path
            return (Path(verified_libc_path), Path(ld_ret), verified_libc_impl)
        assert verified_ld_path is not None
        # We didn't get an approved libc path.
        # Lets ask the libc if it wants us to return the same path for the libc as for the ld,
        # or try to get an libc candidate.
        if not verified_libc_impl.libc_same_as_ld() and possible_libc_paths:
            libc_ret = possible_libc_paths[0]
        else:
            libc_ret = verified_ld_path
        return (Path(verified_ld_path), Path(libc_ret), verified_libc_impl)

    # Noone approved anything. If we have any candidate paths return them, otherwise raise exception.
    if possible_libc_paths and possible_ld_paths:
        return (Path(possible_libc_paths[0]), Path(possible_ld_paths[0]), unknown)
    if possible_libc_paths:
        return (Path(possible_libc_paths[0]), Path(possible_libc_paths[0]), unknown)
    if possible_ld_paths:
        return (Path(possible_ld_paths[0]), Path(possible_ld_paths[0]), unknown)
    # NOTE: We could also try to verify all of the other mappings in the address space, which would
    # sometimes yield us correct detection if the libc is very weirdly named, but it might be rare
    # enough and slow enough that it's not worth it. Not sure.
    # But if none of those get approved, we shouldn't return the first "candidate" match but really
    # raise.
    raise LibcNotFound("No candidate libc or ld mappings found.")


@pwndbg.lib.cache.cache_until("start", "objfile")
def get_libc() -> LibcProvider:
    _, _, libc = __get_libc()
    return libc


def which() -> LibcType:
    libc: LibcProvider = get_libc()
    return libc.type()


# ======== Public API =========


def has_exported_symbols() -> bool:
    """
    Do we have exported library symbols (e.g. fscanf, read, write)?

    If the library is dynamically linked, they will always be there. If it is statically
    linked and stripped, they may be missing.
    """
    return util.has_exported_symbols(str(filepath()))


def has_internal_symbols() -> bool:
    """
    Do we have internal library symbols?

    If the library is dynamically linked, even if it is stripped it will retain its
    exported symbols (e.g. fscanf) because they are required for dynamic linking.

    This funcions checks if the non-exported symbols (like __GI_exit, __run_exit_handlers,
    intitial) are also available.

    Symbols are global variables and functions. Internal symbols also come with debug info.
    """
    path, _, libc = __get_libc()
    return libc.has_internal_symbols(str(path))


def has_debug_info() -> bool:
    """
    Do we have debugging information like structure types?
    """
    libc: LibcProvider = get_libc()
    return libc.has_debug_info()


def filepath() -> Path:
    """
    The filepath of the libc shared object.

    There may not be a backing file for this Path if we are remote debugging.
    If the program is statically linked this will return the path of the main
    objfile.
    This may have the same value as loader_filepath() for some libc's.
    """
    path, _, _ = __get_libc()
    return path


def loader_filepath() -> Path:
    """
    The filepath of the ld shared object.

    There may not be a backing file for this Path if we are remote debugging.
    If the program is statically linked this will return the path of the main
    objfile.
    This may have the same value as filepath() for some libc's.
    """
    _, path, _ = __get_libc()
    return path


def addr() -> int:
    """
    The start load address of the libc shared object file.

    If the program is statically linked this will return the address of the main
    objfile.
    May be the same as loader_addr() for some libc's.
    """
    yes = pwndbg.aglib.vmmap.named_region_start(str(filepath()))
    if yes is None:
        raise LibcNotFound(
            "Binary path from filepath() is not listed in memory maps "
            "(e.g. Linux kernel / vmlinux is not mapped like a userspace ELF)."
        )
    return yes


def loader_addr() -> int:
    """
    The start load address of the ld shared object file.

    If the program is statically linked this will return the address of the main
    objfile.
    May be the same as addr() for some libc's.
    """
    yes = pwndbg.aglib.vmmap.named_region_start(str(loader_filepath()))
    if yes is None:
        raise LibcNotFound(
            "Binary path from loader_filepath() is not listed in memory maps "
            "(e.g. Linux kernel / vmlinux is not mapped like a userspace ELF)."
        )
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
    libc: LibcProvider = get_libc()
    try:
        ver = version()
        return libc.urls(ver)
    except NotImplementedError:
        return libc.urls(None)


def version() -> tuple[int, ...]:
    """
    Get the version of the libc implementation as a tuple.

    If you are calling this, you must know exactly which libc is being used.

    If the version couldn't be determined, (-1, -1) will be returned.
    """
    path, _, libc = __get_libc()
    return libc.version(str(path))


# ======== End of Public API =========
