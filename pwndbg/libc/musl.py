from __future__ import annotations

from .api import LibcType


def initialize() -> bool:
    return True


def get_version() -> tuple[int, ...]:
    return (1, 1)


def is_being_used() -> bool:
    return True


def type() -> LibcType:
    return LibcType.GLIBC
