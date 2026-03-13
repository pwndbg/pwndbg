"""
Perform queries specific to the musl libc.
"""

from __future__ import annotations

import pwndbg.aglib.elf
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.lib.cache

from . import util
from .dispatch import LibcType
from .dispatch import LibcURLs

# Precomputed byte patterns for musl's mallocng size_classes array (uint16_t[48]).
# Present in any musl binary that calls malloc(). Works for musl v1.2.1+ (when
# mallocng replaced oldmalloc).
# https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/malloc.c#L12
#
# Generated with:
#   import struct
#   sc = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 18, 20, 25, 31, 36, 42,
#         50, 63, 72, 84, 102, 127, 146, 170, 204, 255, 292, 340, 409, 511,
#         584, 682, 818, 1023, 1169, 1364, 1637, 2047, 2340, 2730, 3276,
#         4095, 4680, 5460, 6552, 8191]
#   struct.pack(f"<{len(sc)}H", *sc)  # little-endian
#   struct.pack(f">{len(sc)}H", *sc)  # big-endian
# fmt: off
_MALLOCNG_SIZE_CLASSES_LE = (
    b"\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00"
    b"\x09\x00\x0a\x00\x0c\x00\x0f\x00\x12\x00\x14\x00\x19\x00\x1f\x00"
    b"\x24\x00\x2a\x00\x32\x00\x3f\x00\x48\x00\x54\x00\x66\x00\x7f\x00"
    b"\x92\x00\xaa\x00\xcc\x00\xff\x00\x24\x01\x54\x01\x99\x01\xff\x01"
    b"\x48\x02\xaa\x02\x32\x03\xff\x03\x91\x04\x54\x05\x65\x06\xff\x07"
    b"\x24\x09\xaa\x0a\xcc\x0c\xff\x0f\x48\x12\x54\x15\x98\x19\xff\x1f"
)
_MALLOCNG_SIZE_CLASSES_BE = (
    b"\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08"
    b"\x00\x09\x00\x0a\x00\x0c\x00\x0f\x00\x12\x00\x14\x00\x19\x00\x1f"
    b"\x00\x24\x00\x2a\x00\x32\x00\x3f\x00\x48\x00\x54\x00\x66\x00\x7f"
    b"\x00\x92\x00\xaa\x00\xcc\x00\xff\x01\x24\x01\x54\x01\x99\x01\xff"
    b"\x02\x48\x02\xaa\x03\x32\x03\xff\x04\x91\x05\x54\x06\x65\x07\xff"
    b"\x09\x24\x0a\xaa\x0c\xcc\x0f\xff\x12\x48\x15\x54\x19\x98\x1f\xff"
)
# fmt: on


def type() -> LibcType:
    return LibcType.MUSL


@pwndbg.lib.cache.cache_until("start", "objfile")
def version(libc_filepath: str) -> tuple[int, ...]:
    # __libc_version is an internal symbol in musl, added in version v1.1.21
    # https://elixir.bootlin.com/musl/v1.1.21/source/src/internal/version.c#L4
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("__libc_version", objfile_endswith=libc_filepath)
    if addr is not None:
        ver = pwndbg.aglib.memory.string(addr)
        return util.version_parse(ver)

    # The version string is simply not embedded into older versions of musl afaict.
    return (-1, -1)


@pwndbg.lib.cache.cache_until("start", "objfile")
def has_internal_symbols(libc_filepath: str) -> bool:
    # c_messages is an internal global variable in musl. Has existed since the
    # first release i.e. version v0.5.0 (2011). (elixir doesn't have 0.5.0 on hand)
    # https://elixir.bootlin.com/musl/v0.5.9/source/src/locale/langinfo.c#L24
    return (
        pwndbg.aglib.symbol.lookup_symbol("c_messages", objfile_endswith=libc_filepath) is not None
    )


@pwndbg.lib.cache.cache_until("start", "objfile")
def has_debug_info() -> bool:
    # Available since the first release (0.5.0). (elixir doesn't have 0.5.0 on hand)
    # https://elixir.bootlin.com/musl/v0.5.9/source/include/bits/pthread.h#L1
    return pwndbg.aglib.typeinfo.load("struct __ptcb") is not None


def verify_libc_candidate(mapping_name: str) -> bool:
    # First check __freadahead which is an exported symbol in musl, and bionic but not in glibc
    # It was introduced in v0.9.2 (year 2012)
    # https://elixir.bootlin.com/musl/v0.9.2/source/src/stdio/ext2.c#L3
    if (
        util.has_exported_symbols(mapping_name)
        and pwndbg.aglib.symbol.lookup_symbol("__freadahead", objfile_endswith=mapping_name) is None
    ):
        return False

    # Then do a consistent but more expensive (?) check:
    # Check if the string "/tmp/tmpnam_XXXX" is in the .rodata of the binary.
    # Added in musl version v1.1.2 (year 2014) (is present until at least v1.2.5).
    # https://elixir.bootlin.com/musl/v1.1.2/source/src/stdio/tmpnam.c#L15
    rodata: tuple[int, int, bytes] | None = pwndbg.aglib.elf.section_by_name(
        mapping_name, ".rodata", try_local_path=True
    )
    if rodata is None:
        return False
    _, _, data = rodata
    if b"/tmp/tmpnam_XXXX" in data:
        return True

    # Fallback for statically linked musl: the tmpnam string may be absent because
    # the linker only includes referenced code/data. Instead, look for mallocng's
    # size_classes array, which is present in any program that calls malloc().
    return _MALLOCNG_SIZE_CLASSES_LE in data or _MALLOCNG_SIZE_CLASSES_BE in data


def verify_ld_candidate(mapping_name: str) -> bool:
    # For musl, ld and libc are the same mapping.
    # On some distributions it is named libc, on some it's ld.
    return verify_libc_candidate(mapping_name)


def urls(ver: tuple[int, ...] | None) -> LibcURLs:
    assert ver is not None
    if ver[0] == -1:
        # Version not available, use dummy values.
        return LibcURLs(
            versioned_readable_source="https://elixir.bootlin.com/musl/latest/source",
            versioned_compressed_source="https://musl.libc.org/releases/musl-<major>.<minor>.<patch>.tar.gz",
            homepage="https://musl.libc.org/",
            git="git://git.musl-libc.org/musl",
        )

    ver_str = ".".join(map(str, ver))
    return LibcURLs(
        versioned_readable_source=f"https://elixir.bootlin.com/musl/v{ver_str}/source",
        versioned_compressed_source=f"https://musl.libc.org/releases/musl-{ver_str}.tar.gz",
        homepage="https://musl.libc.org/",
        git="git://git.musl-libc.org/musl",
    )


def libc_same_as_ld() -> bool:
    return True
