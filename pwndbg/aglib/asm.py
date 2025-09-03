from __future__ import annotations

import pathlib
from typing import List

import pwnlib.context
import pwnlib.data

import pwndbg.aglib.arch
import pwndbg.lib.zig


def _get_pwntools_includes() -> List[pathlib.Path]:
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
    return pwndbg.lib.zig.asm(pwndbg.aglib.arch, data, includes=_get_pwntools_includes())
