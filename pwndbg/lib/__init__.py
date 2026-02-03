"""
Library for non-debugger-dependant functionality.
"""

from __future__ import annotations

from pwndbg.lib.err import ErrorCode
from pwndbg.lib.err import Status
from pwndbg.lib.err import TypeNotFound
from pwndbg.lib.err import TypeNotRecovered

__all__ = [
    "ErrorCode",
    "Status",
    "TypeNotRecovered",
    "TypeNotFound",
]
