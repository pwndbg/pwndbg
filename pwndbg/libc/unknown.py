"""
Answers libc-specific questions in a non-commital way when
we don't know which libc implementation we are actually using.
"""

from __future__ import annotations

from .dispatch import LibcType
from .dispatch import LibcURLs


def type() -> LibcType:
    return LibcType.UNKNOWN


def _is_being_used() -> bool:
    return True


def version(libc_filepath: str) -> tuple[int, ...]:
    return (-1, -1)


def has_internal_symbols(libc_filepath: str) -> bool:
    return False


def has_debug_info() -> bool:
    return False


def verify_libc_candidate(mapping_name: str) -> bool:
    # We cheat a bit and return False for both
    # verify_libc_candidate and verify_ld_candidate.
    return False


def verify_ld_candidate(mapping_name: str) -> bool:
    return False


def urls(ver: tuple[int, ...] | None) -> LibcURLs:
    return LibcURLs(
        versioned_readable_source="not available",
        versioned_compressed_source="not available",
        homepage="not available",
        git="not available",
    )


def libc_same_as_ld() -> bool:
    return False
