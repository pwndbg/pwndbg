from __future__ import annotations

from typing import Literal

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform


def osabi(arch: ArchDefinition) -> str | None:
    """
    Return the OS ABI part of the target triple.

    The arch argument must be `pwndbg.aglib.arch`.

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
        arch: must be pwndbg.aglib.arch
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


