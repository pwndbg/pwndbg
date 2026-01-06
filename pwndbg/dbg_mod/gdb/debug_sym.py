from __future__ import annotations

import re

import gdb


def _get_debug_file_directory() -> str:
    """
    Retrieve the debug file directory path.

    The debug file directory path ('show debug-file-directory') is a comma-
    separated list of directories which GDB will look in to find the binaries
    currently loaded.
    """
    result = gdb.execute("show debug-file-directory", to_string=True, from_tty=False)
    expr = r'The directory where separate debug symbols are searched for is "(.*)".\n'

    match = re.search(expr, result)

    if match:
        return match.group(1)
    return ""


def _set_debug_file_directory(d: str) -> None:
    gdb.execute(f"set debug-file-directory {d}", to_string=True, from_tty=False)


def _add_debug_file_directory(d: str) -> None:
    current = _get_debug_file_directory()
    if current:
        _set_debug_file_directory(f"{current}:{d}")
    else:
        _set_debug_file_directory(d)


if "/usr/lib/debug" not in _get_debug_file_directory():
    _add_debug_file_directory("/usr/lib/debug")
