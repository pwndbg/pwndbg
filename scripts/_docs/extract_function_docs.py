#!/usr/bin/env python
from __future__ import annotations

import json
import re
from collections.abc import Callable
from collections.abc import Sequence
from dataclasses import asdict
from inspect import getdoc
from inspect import signature
from typing import Any
from typing import Protocol

import pwndbg
from scripts._docs.function_docs_common import ExtractedFunction
from scripts._docs.function_docs_common import extracted_filename
from scripts._docs.gen_docs_generic import get_debugger


class ConvFunction(Protocol):
    func: Callable[..., Any]
    name: str
    __doc__: str


def sanitize_signature(func_name: str, sig: str) -> str:
    """
    We need to strip ' from type annotations, and cleanup
    some functions that don't display properly.
    """
    sig = sig.replace("'", "")

    # Fixup default values. Example, change this:
    # fsbase(offset: gdb.Value = <gdb.Value object at 0x7fb49fd2b9b0>) -> int
    #   into
    # fsbase(offset: gdb.Value = gdb.Value(0)) -> int
    # Unfortunately, I don't know how to extract the `0` from gdb.Value(0), and
    # the number can be any arbitrary number so I cannot just count on it being zero.
    # Thus, we will hardcode the doc fixes here (thankfully there aren't too many
    # functions like this).
    gdb_value_fixups: dict[str, int] = {
        # convenience function name: the value inside gdb.Value(<this one>)
        "fsbase": 0,
        "gsbase": 0,
        "heap": 0,
        "stack": 0,
        "bss": 0,
        "got": 0,
        "percpu": -1,
    }
    if func_name in gdb_value_fixups:
        sig = re.sub(
            r"<gdb\.Value object at 0x[0-9a-fA-F]+>",
            f"gdb.Value({gdb_value_fixups[func_name]})",
            sig,
        )

    return sig


def extract_functions() -> Sequence[ConvFunction]:
    """
    Returns a dictionary that mapes function names to
    the corresponding _GdbFunction objects.
    """
    # https://github.com/astral-sh/ruff/issues/22467
    global pwndbg
    if pwndbg.dbg.is_gdblib_available():
        import pwndbg.gdblib.functions

        functions = pwndbg.gdblib.functions.functions
    else:
        functions = []

    return functions


def distill_sources(funcs: Sequence[ConvFunction]) -> list[ExtractedFunction]:
    result: list[ExtractedFunction] = []

    for func in funcs:
        name = func.name
        signa = sanitize_signature(name, str(signature(func.func)))
        docstr = getdoc(func)
        assert docstr

        result.append(ExtractedFunction(name, signa, docstr))

    return result


def main():
    print("\n== Extracting Functions ==")

    debugger = get_debugger()

    funcs = extract_functions()
    extracted = distill_sources(funcs)

    result = [asdict(x) for x in extracted]

    # Write to file.
    out_path = extracted_filename(debugger)
    with open(out_path, "w") as file:
        json.dump(result, file)

    print("== Finished Extracting Functions ==")


# Not checking __name__ due to lldb
# (even though it doesn't support functions /shrug).
main()
