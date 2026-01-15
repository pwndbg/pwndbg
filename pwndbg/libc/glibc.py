"""
Get information about the GLibc
"""

from __future__ import annotations

import functools
import os
import re
from collections.abc import Callable
from typing import TypeVar

from elftools.elf.relocation import Relocation
from typing_extensions import ParamSpec

import pwndbg.aglib.elf
import pwndbg.aglib.heap
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.lib.cache
import pwndbg.lib.config
from pwndbg.color import message
from pwndbg.lib.config import Scope

from . import common
from .api import LibcType

P = ParamSpec("P")
T = TypeVar("T")

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
def _get_version() -> tuple[int, ...]:
    if has_symbols():
        addr = pwndbg.aglib.symbol.lookup_symbol_addr("__libc_version")
        if addr is None:
            raise ValueError("Glibc has symbols but doesn't have the __libc_version symbol?")

        ver = pwndbg.aglib.memory.string(addr)
        return tuple(int(_) for _ in ver.split(b"."))

    libc_filename = get_libc_filename_from_info_sharedlibrary()
    if not libc_filename:
        return None
    result = pwndbg.aglib.elf.section_by_name(libc_filename, ".rodata", try_local_path=True)
    if result is None:
        return None
    _, _, data = result
    banner_start = data.find(b"GNU C Library")
    if banner_start == -1:
        return None
    banner = data[banner_start : data.find(b"\x00", banner_start)]
    ret = re.search(rb"release version (\d+)\.(\d+)", banner)
    return tuple(int(_) for _ in ret.groups()) if ret else None


@pwndbg.lib.cache.cache_until("start", "objfile")
def get_libc_filename_from_info_sharedlibrary() -> str | None:
    """
    Get the filename of the libc by parsing the output of `info sharedlibrary`.
    """
    possible_libc_path: list[str] = []
    i = pwndbg.dbg.selected_inferior()

    main_module_name = i.main_module_name()
    seen = set()
    for address, size, sect_name, module_name in i.module_section_locations():
        if module_name in seen:
            continue
        seen.add(module_name)

        if module_name == main_module_name:
            continue

        path = module_name
        basename = os.path.basename(
            path[7:] if path.startswith("target:") else path
        )  # "target:" prefix is for remote debugging
        if basename == "libc.so.6":
            # The default filename of libc should be libc.so.6, so if we found it, we just return it directly.
            return path
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


# ===== Libc Interaface Implementation =====


def type() -> LibcType:
    return LibcType.GLIBC


def is_being_used() -> bool:
    return True


def initialize() -> bool:
    return True


def version() -> tuple[int, ...]:
    if glibc_version:
        version_tuple = tuple(int(i) for i in glibc_version.value.split("."))
        return version_tuple

    return _get_version()


def has_symbols() -> bool:
    return True


def has_debug_info() -> bool:
    return pwndbg.aglib.typeinfo.load("struct malloc_chunk") is not None


def filename() -> str:
    return ""


def loader_filename() -> str:
    return ""


def mapping() -> str:
    return ""


def loader_mapping() -> str:
    return ""


def relocations_by_section_name(section_name: str) -> tuple[Relocation, ...]:
    return common.relocations_by_section_name(section_name, filename())


def section_address_by_name(section_name: str) -> int:
    return common.section_address_by_name(section_name, filename())


def source_url() -> str:
    ver = version()
    ver_str = ".".join(map(str, ver))
    return f"https://elixir.bootlin.com/glibc/glibc-{ver_str}/source"


# ===== End of Libc Interaface Implementation =====


def OnlyWhenGlibcLoaded(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWhenGlibcLoaded(*a: P.args, **kw: P.kwargs) -> T | None:
        if is_being_used():
            return function(*a, **kw)

        print(f"{function.__name__}: GLibc not loaded yet.")
        return None

    return _OnlyWhenGlibcLoaded


@OnlyWhenGlibcLoaded
def check_safe_linking() -> bool:
    """
    Safe-linking is a glibc 2.32 mitigation; see:
    - https://lanph3re.blogspot.com/2020/08/blog-post.html
    - https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/
    """
    return (version() >= (2, 32) or safe_lnk.value) and safe_lnk.value is not False
