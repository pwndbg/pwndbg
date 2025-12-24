from __future__ import annotations

import pathlib
from typing import List

import pwnlib.context
import pwnlib.data

import pwndbg.aglib
import pwndbg.lib.zig
from pwndbg.aglib.arch_mod import PwndbgArchitecture
from pwndbg.aglib.arch_mod import get_pwndbg_architecture
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE


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


def asm_for_arch(data: str, arch_type: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> bytes:
    """
    Assemble the `data` string for the provided architecture and return the assembled bytes.
    """
    # If a valid arch_type is passed to asm_for_arch, this should never return None.
    arch: PwndbgArchitecture | None = get_pwndbg_architecture(arch_type)
    assert arch is not None
    return pwndbg.lib.zig.asm(arch, data, includes=_get_pwntools_includes())


def asm(data: str) -> bytes:
    """
    Assemble the `data` string for the current architecture and return the assembled bytes.

    Only call this if the pwndbg.aglib.arch is not None (i.e. the inferior has started).
    """
    return pwndbg.lib.zig.asm(pwndbg.aglib.arch, data, includes=_get_pwntools_includes())
