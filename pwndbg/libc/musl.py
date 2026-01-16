from __future__ import annotations

from pathlib import Path

from elftools.elf.relocation import Relocation

from .dispatch import LibcType
from .dispatch import LibcURLs


def type() -> LibcType:
    return LibcType.MUSL


# The _is_being_used check may be relatively heavy-weight, but it shouldn't be.
# There is also a notion of, if I *know* that I am being used, then I probably shouldn't
# clear the cache on objfile, but only on start. This could be a significant performance
# boon.

# I guess it would make a lot of sense if the filepath() implementation was mostly libc-agnostic
# so it can be leveraged in _is_being_used() and friends.

# FIXME: you should be able to do:
# libc.get()._version() and libc.glibc.version() but not libc.get().version()
# it doesn't make sense to ask about the version of a generic libc, what are you doing?.

def _is_being_used() -> bool:
    # TODO
    # First check __freadahead which is available in musl, and bionic but not in glibc
    # More consistent check:
    # Check if the string "/tmp/tmpnam_XXXX" is in the .rodata of the binary.
    # Added in musl version v1.1.2 (is present until at least v1.2.5).
    # https://elixir.bootlin.com/musl/v1.1.2/source/src/stdio/tmpnam.c#L15
    return True


def version() -> tuple[int, ...]:
    raise NotImplementedError


def has_symbols() -> bool:
    return True


def has_debug_info() -> bool:
    return True

def verify_libc_candidate(mapping_name: str) -> bool:
    ...


def verify_ld_candidate(mapping_name: str) -> bool:
    return verify_libc_candidate(mapping_name)


def urls() -> LibcURLs:
    # FIXME: Can we get the version somehow?
    return LibcURLs(
        versioned_readable_source="https://elixir.bootlin.com/musl/latest/source",
        versioned_compressed_source="https://musl.libc.org/releases/musl-1.2.5.tar.gz",
        homepage="https://musl.libc.org/",
        git="git://git.musl-libc.org/musl",
    )
