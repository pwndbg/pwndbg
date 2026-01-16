"""
Perform queries specific to the musl libc.

This should never use .facade .
"""

from __future__ import annotations

import pwndbg.aglib.elf
import pwndbg.aglib.symbol
from pwndbg.lib.common import UncertainDecision

from .dispatch import LibcType
from .dispatch import LibcURLs


def type() -> LibcType:
    return LibcType.MUSL


# FIXME: you should be able to do:
# libc.get()._version() and libc.glibc.version() but not libc.get().version()
# it doesn't make sense to ask about the version of a generic libc, what are you doing?.


def version() -> tuple[int, ...]:
    raise NotImplementedError


def has_symbols() -> bool:
    return True


def has_debug_info() -> bool:
    return True


def verify_libc_candidate(mapping_name: str) -> UncertainDecision:
    # First check __freadahead which is available in musl, and bionic but not in glibc
    if pwndbg.aglib.symbol.lookup_symbol("__freadahead", objfile_endswith=mapping_name) is None:
        return UncertainDecision.NO
    else:
        # Then do a consistent but more expensive (?) check:
        # Check if the string "/tmp/tmpnam_XXXX" is in the .rodata of the binary.
        # Added in musl version v1.1.2 (is present until at least v1.2.5).
        # https://elixir.bootlin.com/musl/v1.1.2/source/src/stdio/tmpnam.c#L15
        rodata: tuple[int, int, bytes] | None = pwndbg.aglib.elf.section_by_name(
            mapping_name, ".rodata", try_local_path=True
        )
        if rodata is None:
            return UncertainDecision.NO
        _, _, data = rodata
        if b"/tmp/tmpnam_XXXX" in data:
            return UncertainDecision.YES
        else:
            return UncertainDecision.NO


def verify_ld_candidate(mapping_name: str) -> UncertainDecision:
    # For musl, ld and libc are the same mapping.
    # On some distributions it is named libc, on some it's ld.
    return verify_libc_candidate(mapping_name)


def urls() -> LibcURLs:
    # FIXME: Can we get the version somehow?
    return LibcURLs(
        versioned_readable_source="https://elixir.bootlin.com/musl/latest/source",
        versioned_compressed_source="https://musl.libc.org/releases/musl-1.2.5.tar.gz",
        homepage="https://musl.libc.org/",
        git="git://git.musl-libc.org/musl",
    )
