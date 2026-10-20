from __future__ import annotations

import os
from typing import Literal

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform


def osabi(arch: ArchDefinition) -> str | None:
    """
    Return the OS ABI part of the target triple.

    `arch` must be aglib.arch

    FIXME: Do we care about bare metal or musl etc?
    """
    if arch.platform == Platform.LINUX:
        # "gnu", "gnuabin32", "gnuabi64", "gnueabi", "gnueabihf",
        # "gnuf32","gnusf", "gnux32", "gnuilp32",
        # TODO: support soft/hard float abi?
        return "linux-gnu"

    if arch.platform == Platform.DARWIN:
        return "macos-none"

    return None


def compiler_target_triple(
    arch: ArchDefinition,
    arch_mapping: dict[
        tuple[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Literal["little", "big"], int], str
    ],
) -> str | None:
    """
    Get the target triple for the relevant compiler invocation.

    Doesn't make sense for GCC since it varies by distro.

    Arguments:
        arch: must be aglib.arch
        arch_mapping: the mapping from pwndbg to the compiler architecture in the triple

    Returns:
        The target triple string if all is valid, otherwise None.
    """
    osabi_ = osabi(arch)
    if osabi_ is None:
        return None

    arch_mapping_ = arch_mapping.get((arch.name, arch.endian, arch.ptrsize))
    if arch_mapping_ is None:
        return None

    return f"{arch_mapping_}-{osabi_}"


def path_dictionary() -> dict[str, str]:
    """
    Returns a (basename -> full path) dictionary for
    every binary in PATH.

    This takes a *while* to run (~200ms), cache it.

    (maybe this func should not be in this file)
    """
    # I would use pathlib here but it makes it slower :(
    seen_dirs: set[str] = set()
    found: dict[str, str] = {}
    for d in os.environ.get("PATH", os.defpath).split(os.pathsep):
        if d == "":
            # otherwise the fs stuff gets messy
            continue

        real = os.path.realpath(d)
        if real in seen_dirs:
            continue
        seen_dirs.add(real)

        try:
            entries = os.scandir(real)
        except OSError:
            continue

        for entry in entries:
            if entry.name in found:
                continue
            try:
                if entry.is_file() and os.access(entry.path, os.X_OK):
                    found[entry.name] = entry.path
            except OSError:
                continue
    return found


def all_bins_in_path() -> list[str]:
    """
    Get the path of every executable in PATH.

    This takes a *while* to run (~200ms), cache it.

    (maybe this func should not be in this file)
    """
    return list(path_dictionary().values())
