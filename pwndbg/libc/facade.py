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
from pwndbg.lib.common import UncertainDecision

from . import glibc
from . import musl
from . import unknown
from .dispatch import LibcType
from .dispatch import LibcURLs
from .dispatch import LibcWrangler

# Order is important.
_libc_implementations: tuple[LibcWrangler, ...] = (glibc, musl, unknown)


class LibcNotFound(Exception):
    pass


def __check_candidates(
    libc_candidates: list[str], ld_candidates: list[str]
) -> tuple[str | None, str | None, LibcWrangler | None]:
    """
    Queries the libc implementations on if any of them claim any libc and ld mappings.

    Returns:
        A tuple (claimed libc mapping, claimed ld mapping, claiming implementation). If noone claimed anything,
        "claiming implementation" will be None. It is possible that exactly one of "claimed libc mapping"
        and "claimed ld mapping" is None.
    """

    def verify_libc_path(path: str) -> tuple[bool, LibcWrangler]:
        for impl in _libc_implementations:
            if impl.verify_libc_candidate(path) == UncertainDecision.YES:
                # Someone claims that this makes sense!
                return True, impl
        return False, unknown

    def verify_ld_path(path: str) -> tuple[bool, LibcWrangler]:
        for impl in _libc_implementations:
            if impl.verify_ld_candidate(path):
                # Someone claims that this makes sense!
                return True, impl
        return False, unknown

    verified_libc_path: str | None = None
    verified_ld_path: str | None = None
    verified_libc_impl: LibcWrangler | None = None

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
def __get_libc() -> tuple[Path, Path, LibcWrangler]:
    """
    Find the active libc implementation and the associated libc and ld mappings.

    The process must be alive when this is called.

    If the program is statically linked, will return the main executable module's
    Path for the libc and ld path, and still try to infer the libc implementation.

    If a libc implementation approves only a libc mapping but not an ld mapping or
    vice-versa, that mapping will be returned both as the libc and ld mapping.

    If no libc verifies anything, but there is at least one libc OR ld candidate
    mapping, it/they will be returned along with the "unknown" libc implementation.

    Returns:
        A tuple (libc mapping path, ld mapping path, libc implementation).

    Raises:
        LibcNotFound - If the binary is dynamically linked and we couldn't find
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
        if certain_libc_path is None:
            if basename in exact_libc_basename_matches:
                # This is exceedingly likely to be the correct module.
                certain_libc_path = path
        elif libc_regex.search(basename) is not None:
            # Maybe the user loaded the libc with LD_PRELOAD.
            # Some common libc names: libc-2.36.so, libc6_2.36-0ubuntu4_amd64.so, libc.so
            possible_libc_paths.append(path)

        # Check for ld
        if certain_ld_path is None:
            if basename in exact_ld_basename_matches:
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
    verified: tuple[str | None, str | None, LibcWrangler | None] = __check_candidates(
        possible_libc_paths, possible_ld_paths
    )
    verified_libc_path, verified_ld_path, verified_libc_impl = verified

    if verified_libc_impl is not None:
        # Someone approved something!
        # NOTE: It is maybe contravesial that I return the libc path if only the ld path is found and vice versa.
        # This is necessary for some libc's like musl where the libc and the ld are always the same mapping,
        # but it strictly incorrect for other libc's like glibc. I guess we could ask the libc implementation
        # what it wants us to do and raise an exception if we are in the "strictly incorrect" option.
        # I'm choosing not to do that because I feel it simply might not actually be a problem for any users of
        # this, and I'd rather not raise if at all possible to accomodate as many setups as possible.
        # We can change it later if it ends up troublesome.
        if verified_libc_path is not None and verified_ld_path is not None:
            return (Path(verified_libc_path), Path(verified_ld_path), verified_libc_impl)
        elif verified_libc_path is not None:
            return (Path(verified_libc_path), Path(verified_libc_path), verified_libc_impl)
        else:
            assert verified_ld_path is not None
            return (Path(verified_ld_path), Path(verified_ld_path), verified_libc_impl)

    # Noone approved anything. If we have any candidate paths return them, otherwise raise exception.
    if possible_libc_paths and possible_ld_paths:
        return (Path(possible_libc_paths[0]), Path(possible_ld_paths[0]), unknown)
    elif possible_libc_paths:
        return (Path(possible_libc_paths[0]), Path(possible_libc_paths[0]), unknown)
    elif possible_ld_paths:
        return (Path(possible_ld_paths[0]), Path(possible_ld_paths[0]), unknown)
    else:
        # NOTE: We could also try to verify all of the other mappings in the address space, which would
        # sometimes yield us correct detection if the libc is very wierdly named, but it might be rare
        # enough and slow enough that it's not worth it. Not sure.
        # But if none of those get approved, we shouldn't return the first "candidate" match but really
        # raise.
        raise LibcNotFound("No candidate libc or ld mappings found.")


@pwndbg.lib.cache.cache_until("start", "objfile")
def get_libc() -> LibcWrangler:
    _, _, libc = __get_libc()
    return libc


def which() -> LibcType:
    libc: LibcWrangler = get_libc()
    return libc.type()


# ======== Public API =========


def has_symbols() -> bool:
    """
    Can we read out global variables and functions in the libc object file?
    """
    path, _, libc = __get_libc()
    return libc.has_symbols(str(path))


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
    path, _, _ = __get_libc()
    return path


def loader_filepath() -> Path:
    """
    The filepath of the ld shared object.

    There may not be a backing file for this Path if we are remote debugging.
    This may have the same value as filepath() for some libc's.
    """
    _, path, _ = __get_libc()
    return path


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


def version() -> tuple[int, ...]:
    """
    Get the version of the libc implementation as a tuple.

    If you are calling this, you must know exactly which libc is being used.

    Some libc's do not implement this and raise a NotImplementedError.
    """
    path, _, libc = __get_libc()
    return libc.version(str(path))


# ======== End of Public API =========
