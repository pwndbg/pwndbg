from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ErrorCode(Enum):
    SUCCESS = 0
    FAILURE = 1
    """Generic failure"""


@dataclass
class Status:
    """
    An error handling object.
    """

    code: ErrorCode
    """An error code associated with this error."""
    message: str = ""
    """If is_failure() returns True, this attribute contains the error message."""

    def is_success(self) -> bool:
        return self.code == ErrorCode.SUCCESS

    def is_failure(self) -> bool:
        return self.code != ErrorCode.SUCCESS

    @staticmethod
    def success() -> Status:
        return Status(ErrorCode.SUCCESS)

    @staticmethod
    def failure(message: str = "") -> Status:
        return Status(ErrorCode.FAILURE, message)

    @staticmethod
    def coded_failure(code: ErrorCode, message: str = "") -> Status:
        return Status(code, message)
