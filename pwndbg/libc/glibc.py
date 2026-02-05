"""
Perform queries specific to the GNU C Library.
"""

from __future__ import annotations

import re

import pwndbg.aglib.elf
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.lib.cache
import pwndbg.lib.config
from pwndbg.color import message
from pwndbg.lib.config import Scope

from . import util
from .dispatch import LibcType
from .dispatch import LibcURLs

safe_lnk = pwndbg.config.add_param(
    "safe-linking",
    None,
    "whether glibc uses safe-linking",
    param_class=pwndbg.lib.config.PARAM_AUTO_BOOLEAN,
)

glibc_version = pwndbg.config.add_param(
    "glibc", "", "glibc version for heap heuristics resolution (e.g. 2.31)", scope=Scope.heap
)


@pwndbg.config.trigger(glibc_version)
def set_glibc_version() -> None:
    ret = re.search(r"^(\d+)\.(\d+)$", glibc_version.value)
    if ret:
        return

    print(
        message.warn(
            f"Invalid GLIBC version: `{glibc_version.value}`, you should provide something like: 2.31 or 2.34"
        )
    )
    glibc_version.revert_default()


@pwndbg.lib.cache.cache_until("start", "objfile")
def _get_version(libc_filepath: str) -> tuple[int, ...]:
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("__libc_version", objfile_endswith=libc_filepath)
    if addr is not None:
        ver = pwndbg.aglib.memory.string(addr)
        return util.version_parse(ver)

    result = pwndbg.aglib.elf.section_by_name(libc_filepath, ".rodata", try_local_path=True)
    if result is None:
        raise Exception(f"Could not retrieve .rodata section of glibc {libc_filepath}")

    _, _, data = result
    banner_start = data.find(b"GNU C Library")
    if banner_start == -1:
        raise Exception(
            f"Could not find 'GNU C Library' in .rodata section of glibc {libc_filepath}"
        )

    banner = data[banner_start : data.find(b"\x00", banner_start)]
    ret = re.search(rb"release version (\d+)\.(\d+)", banner)
    if ret is None:
        raise Exception(
            f"Could not find 'release version' in .rodata section of glibc {libc_filepath}"
        )

    return tuple(int(_) for _ in ret.groups())


# ===== Libc Interface Implementation =====


def type() -> LibcType:
    return LibcType.GLIBC


def version(libc_filepath: str) -> tuple[int, ...]:
    if glibc_version:
        version_tuple = tuple(int(i) for i in glibc_version.value.split("."))
        return version_tuple

    return _get_version(libc_filepath)


# NOTE: Operating under the assumption that debuginfod and add-symbol-file
# trigger the objfile event, making it safe to cache these functions like this.


@pwndbg.lib.cache.cache_until("start", "objfile")
def has_internal_symbols(libc_filepath: str) -> bool:
    # __libc_version exists in all versions of glibc and is an internal symbol.
    # https://elixir.bootlin.com/glibc/glibc-1.90/source/version.c#L23
    return (
        pwndbg.aglib.symbol.lookup_symbol("__libc_version", objfile_endswith=libc_filepath)
        is not None
    )


@pwndbg.lib.cache.cache_until("start", "objfile")
def has_debug_info() -> bool:
    return pwndbg.aglib.typeinfo.load("struct malloc_chunk") is not None


def urls(ver: tuple[int, ...] | None) -> LibcURLs:
    assert ver is not None
    ver_str = ".".join(map(str, ver))
    return LibcURLs(
        versioned_readable_source=f"https://elixir.bootlin.com/glibc/glibc-{ver_str}/source",
        versioned_compressed_source=f"https://ftp.gnu.org/gnu/libc/glibc-{ver_str}.tar.gz",
        homepage="https://sourceware.org/glibc/",
        git="https://sourceware.org/git/glibc.git",
    )


def verify_libc_candidate(mapping_name: str) -> bool:
    if has_internal_symbols(mapping_name):
        # __GI_exit exists since at least version 2.3 (until at least 2.42)
        # https://elixir.bootlin.com/glibc/glibc-2.3/source/include/libc-symbols.h#L670
        # https://elixir.bootlin.com/glibc/glibc-2.3/source/include/libc-symbols.h#L642
        # https://elixir.bootlin.com/glibc/glibc-2.3/source/stdlib/exit.c#L84
        # and I don't see it in other libc's.
        return (
            pwndbg.aglib.symbol.lookup_symbol("__GI_exit", objfile_endswith=mapping_name)
            is not None
        )
    # We don't have internal symbols so we will use a more expensive (?) check:
    rodata: tuple[int, int, bytes] | None = pwndbg.aglib.elf.section_by_name(
        mapping_name, ".rodata", try_local_path=True
    )
    if rodata is None:
        return False
    _, _, data = rodata

    return b"GNU C Library" in data


def verify_ld_candidate(mapping_name: str) -> bool:
    return False


def libc_same_as_ld() -> bool:
    return False


# ===== End of Libc Interface Implementation =====


def check_safe_linking(ver: tuple[int, ...]) -> bool:
    """
    Arguments:
        ver: The version tuple. Pass pwndbg.libc.version() here.

    Safe-linking is a glibc 2.32 mitigation; see:
    - https://lanph3re.blogspot.com/2020/08/blog-post.html
    - https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/
    """
    # FIXME: What if we are not being used?
    return (ver >= (2, 32) or safe_lnk.value) and safe_lnk.value is not False
