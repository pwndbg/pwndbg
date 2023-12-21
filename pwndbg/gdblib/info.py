"""
Runs a few useful commands which are available under "info".
"""

from __future__ import annotations

import re
from typing import Dict
from typing import List
from typing import Tuple

import gdb

import pwndbg.lib.cache

# TODO: Add symbol, threads, dll, program


@pwndbg.lib.cache.cache_until("exit")
def proc_mappings() -> str:
    proc_maps_info = None
    try:
        proc_maps_info = gdb.execute("info proc mappings", to_string=True)
    except gdb.error:
        pass
    return proc_maps_info if proc_maps_info is not None else ""


@pwndbg.lib.cache.cache_until("exit")
def auxv() -> str:
    auxv_info = None
    try:
        auxv_info = gdb.execute("info auxv", to_string=True)
    except gdb.error:
        pass
    return auxv_info if auxv_info is not None else ""


@pwndbg.lib.cache.cache_until("stop")
def files() -> str:
    files_info = None
    try:
        files_info = gdb.execute("info files", to_string=True)
    except gdb.error:
        pass
    return files_info if files_info is not None else ""


def target() -> str:
    target_info = None
    try:
        target_info = gdb.execute("info target", to_string=True)
    except gdb.error:
        pass
    return target_info if target_info is not None else ""


def sharedlibrary() -> str:
    sharedlib_info = None
    try:
        sharedlib_info = gdb.execute("info sharedlibrary", to_string=True)
    except gdb.error:
        pass
    return sharedlib_info if sharedlib_info is not None else ""


def parsed_sharedlibrary() -> Dict[str, Tuple[int, int]]:
    """
    Returns a dictionary of shared libraries with their .text section from and to addresses.
    """
    lines = sharedlibrary().splitlines()
    if len(lines) <= 1:
        return {}

    result: Dict[str, Tuple[int, int]] = {}
    for line in lines:
        # We only need to parse the lines starting with "0x", for example:
        # 0x00007fc8fd01b630  0x00007fc8fd19027d  Yes         /lib/x86_64-linux-gnu/libc.so.6
        # or something like:
        # 0x00007fc8fd01b630  0x00007fc8fd19027d  Yes (*)     /lib/x86_64-linux-gnu/libc.so.6
        if not line.startswith("0x"):
            continue
        from_, to, _, rest = line.split(maxsplit=3)
        path = rest.lstrip("(*)").lstrip()
        result[path] = (int(from_, 0), int(to, 0))
    return result


def sharedlibrary_paths() -> List[str]:
    """
    Get the paths of all shared libraries loaded in the process by parsing the output of "info sharedlibrary".
    """
    return list(parsed_sharedlibrary().keys())


def address(symbol: str) -> int | None:
    try:
        res = gdb.execute(f"info address {symbol}", to_string=True)
        if res is not None:
            match = re.search("0x[0-9a-fA-F]+", res)
            if match:
                return int(match.group(), 0)
        return None
    except gdb.error:
        return None
