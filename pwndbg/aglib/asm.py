from __future__ import annotations

import pathlib

import pwnlib.context
import pwnlib.data

import pwndbg.aglib
import pwndbg.lib.zig


def _get_pwntools_includes() -> list[pathlib.Path]:
    include = (
        pathlib.Path(pwnlib.data.path)
        / "includes"
        / str(pwnlib.context.context.os)
        / f"{pwnlib.context.context.arch}.h"
    )
    if not include.exists():
        return []
    return [include]


def asm(data: str) -> bytes:
    """
    Assemble the `data` string for the current architecture and return the assembled bytes.

    Only call this if the pwndbg.aglib.arch is not None.
    """
    return pwndbg.lib.zig.asm(pwndbg.aglib.arch, data, includes=_get_pwntools_includes())
