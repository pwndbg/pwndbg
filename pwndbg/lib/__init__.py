"""
Library for non-debugger-dependant functionality.
"""

from __future__ import annotations

from pwndbg.lib.err import ErrorCode
from pwndbg.lib.err import Status
from pwndbg.lib.err import SymbolNotRecoveredError
from pwndbg.lib.err import TypeNotFoundError
from pwndbg.lib.err import TypeNotRecoveredError

__all__ = [
    "ErrorCode",
    "Status",
    "TypeNotRecoveredError",
    "TypeNotFoundError",
    "SymbolNotRecoveredError",
]
