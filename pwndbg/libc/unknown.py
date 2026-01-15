from __future__ import annotations

from .api import LibcType


def initialize() -> bool:
    return True


def is_being_used() -> bool:
    return True


def get_version() -> tuple[int, ...]:
    return (0, 0)


def type() -> LibcType:
    return LibcType.UNKNOWN

def has_symbols() -> bool:
    return False

def has_debug_info() -> bool:
    return False

def source_url() -> str:
    return ""
