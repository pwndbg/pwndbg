from __future__ import annotations

import pathlib

import pwnlib.context
import pwnlib.data

import pwndbg.aglib
import pwndbg.lib.compiler


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
    Assemble the `data` string for the passed architecture and return the assembled bytes.

    This does NOT return a runable ELF nor link against the operating system, it returns
    the raw bytes that can be directly run inside a process.

    FIXME: When assembling for armeb this always emits BE32, never BE8, even though there's
    lots of stuff that runs BE8. To emit BE8 we need to add a linking step or fix the bytes
    ourselves.

    Arguments:
        data: the assembly

    Raises:
        CompilerNotFoundError: if a compiler for the target arch could not be found
        DependencyNotFoundError: if objcopy is not present with the associated compiler
        AssemblingError: if the compiler failed to assemble
    """
    return pwndbg.lib.compiler.asm(pwndbg.aglib.arch, data, includes=_get_pwntools_includes())
