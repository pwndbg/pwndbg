"""
Get information about the GLibc
"""

from __future__ import annotations

import functools
import os
import re
from typing import Callable
from typing import List
from typing import Tuple
from typing import TypeVar
from typing import Union
from typing import cast

import gdb
from elftools.elf.relocation import Relocation
from typing_extensions import ParamSpec

import pwndbg.gdblib.elf
import pwndbg.gdblib.file
import pwndbg.gdblib.info
import pwndbg.gdblib.memory
import pwndbg.gdblib.proc
import pwndbg.gdblib.symbol
import pwndbg.gdblib.heap
import pwndbg.lib.cache
import pwndbg.lib.config
import pwndbg.search
from pwndbg.color import message

P = ParamSpec("P")
T = TypeVar("T")

safe_lnk = pwndbg.gdblib.config.add_param(
    "safe-linking",
    None,
    "whether glibc use safe-linking (on/off/auto)",
    param_class=pwndbg.lib.config.PARAM_AUTO_BOOLEAN,
)

glibc_version = pwndbg.gdblib.config.add_param(
    "glibc", "", "GLIBC version for heap heuristics resolution (e.g. 2.31)", scope="heap"
)


@pwndbg.gdblib.config.trigger(glibc_version)
def set_glibc_version() -> None:
    ret = re.search(r"(\d+)\.(\d+)", glibc_version.value)
    if ret:
        glibc_version.value = tuple(map(int, ret.groups()))
        return

    print(
        message.warn(
            f"Invalid GLIBC version: `{glibc_version.value}`, you should provide something like: 2.31 or 2.34"
        )
    )
    glibc_version.revert_default()


@pwndbg.gdblib.proc.OnlyWhenRunning
def get_version() -> Tuple[int, ...] | None:
    return cast(Union[Tuple[int, ...], None], glibc_version) or _get_version()


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def _get_version() -> Tuple[int, ...] | None:
    from pwndbg.gdblib.heap.ptmalloc import GlibcMemoryAllocator

    assert isinstance(pwndbg.gdblib.heap.current, GlibcMemoryAllocator)
    if pwndbg.gdblib.heap.current.libc_has_debug_syms():
        addr = pwndbg.gdblib.symbol.address("__libc_version")
        if addr is not None:
            ver = pwndbg.gdblib.memory.string(addr)
            return tuple(int(_) for _ in ver.split(b"."))
    libc_filename = get_libc_filename_from_info_sharedlibrary()
    if not libc_filename:
        return None
    result = pwndbg.gdblib.elf.dump_section_by_name(libc_filename, ".rodata", try_local_path=True)
    if result is None:
        return None
    _, _, data = result
    banner_start = data.find(b"GNU C Library")
    if banner_start == -1:
        return None
    banner = data[banner_start : data.find(b"\x00", banner_start)]
    ret = re.search(rb"release version (\d+)\.(\d+)", banner)
    return tuple(int(_) for _ in ret.groups()) if ret else None


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def get_libc_filename_from_info_sharedlibrary() -> str | None:
    """
    Get the filename of the libc by parsing the output of `info sharedlibrary`.
    """
    possible_libc_path: List[str] = []
    for path in pwndbg.gdblib.info.sharedlibrary_paths():
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


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def dump_elf_data_section() -> Tuple[int, int, bytes] | None:
    """
    Dump .data section of libc ELF file
    """
    libc_filename = get_libc_filename_from_info_sharedlibrary()
    if not libc_filename:
        # libc not loaded yet, or it's static linked
        return None
    return pwndbg.gdblib.elf.dump_section_by_name(libc_filename, ".data", try_local_path=True)


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def dump_relocations_by_section_name(section_name: str) -> Tuple[Relocation, ...] | None:
    """
    Dump relocations of a section by section name of libc ELF file
    """
    libc_filename = get_libc_filename_from_info_sharedlibrary()
    if not libc_filename:
        # libc not loaded yet, or it's static linked
        return None
    return pwndbg.gdblib.elf.dump_relocations_by_section_name(
        libc_filename, section_name, try_local_path=True
    )


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def get_section_address_by_name(section_name: str) -> int:
    """
    Find section address of libc by section name
    """
    libc_filename = get_libc_filename_from_info_sharedlibrary()
    if not libc_filename:
        # libc not loaded yet, or it's static linked
        return 0
    # TODO: If we are debugging a remote process, this might not work if GDB cannot load the so file
    out = pwndbg.gdblib.info.files()
    for line in out.splitlines():
        if line.endswith(f" is {section_name} in " + libc_filename):
            return int(line.split()[0], 16)
    return 0


def OnlyWhenGlibcLoaded(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWhenGlibcLoaded(*a: P.args, **kw: P.kwargs) -> T | None:
        if get_version() is not None:
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
    return (get_version() >= (2, 32) or safe_lnk) and safe_lnk is not False  # type: ignore[return-value]
