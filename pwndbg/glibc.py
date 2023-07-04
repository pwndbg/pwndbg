"""
Get information about the GLibc
"""

import functools
import os
import re
from typing import Optional
from typing import Tuple

import gdb
from elftools.elf.relocation import Relocation

import pwndbg.gdblib.config
import pwndbg.gdblib.elf
import pwndbg.gdblib.file
import pwndbg.gdblib.info
import pwndbg.gdblib.memory
import pwndbg.gdblib.proc
import pwndbg.gdblib.symbol
import pwndbg.heap
import pwndbg.lib.cache
import pwndbg.search

safe_lnk = pwndbg.gdblib.config.add_param(
    "safe-linking",
    None,
    "whether glibc use safe-linking (on/off/auto)",
    param_class=gdb.PARAM_AUTO_BOOLEAN,
)

glibc_version = pwndbg.gdblib.config.add_param(
    "glibc", "", "GLIBC version for heuristics", scope="heap"
)


@pwndbg.gdblib.proc.OnlyWhenRunning
def get_version() -> Optional[Tuple[int, ...]]:
    if glibc_version.value:
        ret = re.search(r"(\d+)\.(\d+)", glibc_version.value)
        if ret:
            return tuple(int(_) for _ in ret.groups())
        else:
            raise ValueError(
                f"Invalid GLIBC version: `{glibc_version.value}`, you should provide something like: 2.31 or 2.34"
            )
    return _get_version()


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def _get_version() -> Optional[Tuple[int, ...]]:
    if pwndbg.heap.current.libc_has_debug_syms():
        addr = pwndbg.gdblib.symbol.address("__libc_version")
        if addr is not None:
            ver = pwndbg.gdblib.memory.string(addr)
            return tuple(int(_) for _ in ver.split(b"."))
    libc_filename = get_libc_filename_from_info_sharedlibrary()
    if not libc_filename:
        return None
    result = pwndbg.gdblib.elf.dump_section_by_name(libc_filename, ".rodata", try_local_path=True)
    if not result:
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
def get_libc_filename_from_info_sharedlibrary() -> Optional[str]:
    """
    Get the filename of the libc by parsing the output of `info sharedlibrary`.
    """
    # Try to parse the output of `info sharedlibrary`:
    # pwndbg> |info sharedlibrary| grep libc
    # 0x00007f9ade418700  0x00007f9ade58f47d  Yes         ./libc.so.6
    # Or:
    # pwndbg> |info sharedlibrary| grep libc
    # 0x00007f9ade418700  0x00007f9ade58f47d  Yes (*)     ./libc.so.6
    possible_libc_path = []
    for line in pwndbg.gdblib.info.sharedlibrary().splitlines()[1:]:
        if line.startswith("("):
            # footer line:
            # (*): Shared library is missing debugging information.
            break
        path = line.split(maxsplit=3)[-1].lstrip("(*)").lstrip()
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
def dump_elf_data_section() -> Optional[Tuple[int, int, bytes]]:
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
def dump_relocations_by_section_name(section_name: str) -> Optional[Tuple[Relocation, ...]]:
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
def get_data_section_address() -> int:
    """
    Find .data section address of libc
    """
    libc_filename = get_libc_filename_from_info_sharedlibrary()
    if not libc_filename:
        # libc not loaded yet, or it's static linked
        return 0
    # TODO: If we are debugging a remote process, this might not work if GDB cannot load the so file
    out = pwndbg.gdblib.info.files()
    for line in out.splitlines():
        if line.endswith(" is .data in " + libc_filename):
            return int(line.split()[0], 16)
    return 0


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def get_got_section_address() -> int:
    """
    Find .got section address of libc
    """
    libc_filename = get_libc_filename_from_info_sharedlibrary()
    if not libc_filename:
        # libc not loaded yet, or it's static linked
        return 0
    # TODO: If we are debugging a remote process, this might not work if GDB cannot load the so file
    out = pwndbg.gdblib.info.files()
    for line in out.splitlines():
        if line.endswith(" is .got in " + libc_filename):
            return int(line.split()[0], 16)
    return 0


def OnlyWhenGlibcLoaded(function):
    @functools.wraps(function)
    def _OnlyWhenGlibcLoaded(*a, **kw):
        if get_version() is not None:
            return function(*a, **kw)
        else:
            print(f"{function.__name__}: GLibc not loaded yet.")

    return _OnlyWhenGlibcLoaded


@OnlyWhenGlibcLoaded
def check_safe_linking():
    """
    Safe-linking is a glibc 2.32 mitigation; see:
    - https://lanph3re.blogspot.com/2020/08/blog-post.html
    - https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/
    """
    return (get_version() >= (2, 32) or safe_lnk) and safe_lnk is not False
