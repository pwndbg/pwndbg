"""
Get information about the GLibc
"""

import functools
import os
import re

import gdb

import pwndbg.gdblib.config
import pwndbg.gdblib.info
import pwndbg.gdblib.memory
import pwndbg.gdblib.proc
import pwndbg.gdblib.symbol
import pwndbg.heap
import pwndbg.lib.memoize
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
def get_version():
    if glibc_version.value:
        ret = re.search(r"(\d+)\.(\d+)", glibc_version.value)
        if ret:
            return tuple(int(_) for _ in ret.groups())
        else:
            raise ValueError(
                "Invalid GLIBC version: `%s`, you should provide something like: 2.31 or 2.34"
                % glibc_version.value
            )
    return _get_version()


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.memoize.reset_on_start
@pwndbg.lib.memoize.reset_on_objfile
def _get_version():
    if pwndbg.heap.current.libc_has_debug_syms():
        addr = pwndbg.gdblib.symbol.address("__libc_version")
        if addr is not None:
            ver = pwndbg.gdblib.memory.string(addr)
            return tuple([int(_) for _ in ver.split(b".")])
    for addr in pwndbg.search.search(b"GNU C Library"):
        banner = pwndbg.gdblib.memory.string(addr)
        ret = re.search(rb"release version (\d+)\.(\d+)", banner)
        if ret:
            return tuple(int(_) for _ in ret.groups())
    return None


@pwndbg.gdblib.proc.OnlyWhenRunning
@pwndbg.lib.memoize.reset_on_start
@pwndbg.lib.memoize.reset_on_objfile
def get_data_address():
    """
    Find .data section address of libc
    """
    # Try every possible object file, to find which one has `.data` section showed in `info files`
    for libc_filename in (
        objfile.filename
        for objfile in gdb.objfiles()
        if re.search(r"^libc(\.|-.+\.)so", os.path.basename(objfile.filename))
    ):
        # Will `info files` always work? If not, we should probably use `ELFFile` to parse libc file directly
        out = pwndbg.gdblib.info.files()
        for line in out.splitlines():
            if libc_filename in line and " is .data in " in line:
                return int(line.strip().split()[0], 16)
    return 0


def OnlyWhenGlibcLoaded(function):
    @functools.wraps(function)
    def _OnlyWhenGlibcLoaded(*a, **kw):
        if get_version() is not None:
            return function(*a, **kw)
        else:
            print("%s: GLibc not loaded yet." % function.__name__)

    return _OnlyWhenGlibcLoaded


@OnlyWhenGlibcLoaded
def check_safe_linking():
    """
    Safe-linking is a glibc 2.32 mitigation; see:
    - https://lanph3re.blogspot.com/2020/08/blog-post.html
    - https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/
    """
    return (get_version() >= (2, 32) or safe_lnk) and safe_lnk is not False
