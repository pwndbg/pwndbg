#!/usr/bin/env python
from __future__ import annotations

import json
import re
from dataclasses import asdict
from inspect import getdoc
from inspect import signature

import pwndbg
from scripts._docs.function_docs_common import ExtractedFunction
from scripts._docs.function_docs_common import extracted_filename
from scripts._docs.gen_docs_generic import get_debugger

if pwndbg.dbg.is_gdblib_available():
    from pwndbg.gdblib.functions import GdbFunction as ConvFunction
else:
    # Convenience Function - dummy class for debuggers
    # that don't support it.
    class ConvFunction:
        pass


def sanitize_signature(func_name: str, sig: str) -> str:
    """
    We need to strip ' from type annotations, and cleanup
    some functions that don't display properly.
    """
    sig = sig.replace("'", "")
    match func_name:
        case "fsbase":
            sig = re.sub(r"<gdb\.Value object at 0x[0-9a-fA-F]+>", "gdb.Value(0)", sig)
        case "gsbase":
            sig = re.sub(r"<gdb\.Value object at 0x[0-9a-fA-F]+>", "gdb.Value(0)", sig)
    return sig


def extract_functions() -> list[ConvFunction]:
    """
    Returns a dictionary that mapes function names to
    the corresponding _GdbFunction objects.
    """
    if pwndbg.dbg.is_gdblib_available():
        functions = pwndbg.gdblib.functions.functions
    else:
        functions = []

    return functions


def distill_sources(funcs: list[ConvFunction]) -> list[ExtractedFunction]:
    result: list[ExtractedFunction] = []

    for func in funcs:
        name = func.name
        signa = sanitize_signature(name, str(signature(func.func)))
        docstr = getdoc(func)

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
