#!/usr/bin/env python
from __future__ import annotations

from typing import Dict


import pwndbg
from pwndbg.gdblib.functions import _GdbFunction


def extract_functions() -> Dict[str, _GdbFunction]:
    """
    Returns a dictionary that mapes function names to
    the corresponding _GdbFunction objects.
    """
    functions = pwndbg.gdblib.functions.functions
    result = {}

    for f in functions:
        result[f.name] = f

    return result


base_path = "docs/functions/"  # Must have trailing slash.
