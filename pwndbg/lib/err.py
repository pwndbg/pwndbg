"""
The error handling logic.

Contains error and exception definitions.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ErrorCode(Enum):
    """
    Describes which error occurred.

    Feel free to add a new one.
    """

    SUCCESS = 0
    FAILURE = 1
    """Generic failure"""
    NO_STRUCTURE_FILE = 2
    """We tried to load a structure, but the associated structure file doesn't exist."""
    NO_IMPORT = 3
    """We tried to import a python library but it is not installed."""


@dataclass
class Status:
    """
    An error handling object.
    """

    # Inspired by the LLVM Status object:
    # https://github.com/llvm/llvm-project/blob/5a4754d2ced8792be2c21eedfde1ed826f7ef64a/lldb/include/lldb/Utility/Status.h#L118

    code: ErrorCode
    """An error code associated with this error."""
    message: str = ""
    """If is_failure() returns True, this attribute contains the error message."""

    def __init__(self, code: ErrorCode = ErrorCode.SUCCESS, message: str = "") -> None:
        """
        Construct a status object.

        Passing no arguments (i.e. doing `Status()`) represents a success.
        """
        self.code = code
        self.message = message

    def is_success(self) -> bool:
        """Returns True if the Status object denotes a success."""
        return self.code == ErrorCode.SUCCESS

    def is_failure(self) -> bool:
        """Returns True if the Status object denotes a failure."""
        return self.code != ErrorCode.SUCCESS

    @staticmethod
    def succeed() -> Status:
        """Create a Status object that represents a success."""
        return Status()

    @staticmethod
    def fail(message: str = "") -> Status:
        """Create a Status object that represents a generic failure."""
        return Status(ErrorCode.FAILURE, message)

    @staticmethod
    def coded_fail(code: ErrorCode, message: str = "") -> Status:
        """Create a Status object that represents a failure."""
        return Status(code, message)


class TypeNotRecoveredError(Exception):
    """
    We tried to recover (i.e. look up in the debugger and craft ourselves) the
    type `name` but failed because of `msg`.
    """

    def __init__(self, name: str, msg: str) -> None:
        self.name = name
        super().__init__(msg)


class TypeNotFoundError(Exception):
    """
    The type is not in the debugger.
    """


class SymbolNotRecoveredError(Exception):
    """
    We tried to recover (i.e. look up in the debugger and find through heuristics) the
    symbol `name` but failed because of `msg`.
    """

    def __init__(self, name: str, msg: str) -> None:
        self.name = name
        super().__init__(msg)
