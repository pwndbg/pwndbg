"""
Answers libc-specific questions in a non-commital way when
we don't know which libc implementation we are actually using.

This should never use .facade .
"""

from __future__ import annotations

from pwndbg.lib.common import UncertainDecision

from .dispatch import LibcType
from .dispatch import LibcURLs


def type() -> LibcType:
    return LibcType.UNKNOWN


def _is_being_used() -> bool:
    return True


def version(libc_filepath: str) -> tuple[int, ...]:
    raise NotImplementedError


def has_internal_symbols(libc_filepath: str) -> bool:
    return False


def has_debug_info() -> bool:
    return False


def verify_libc_candidate(mapping_name: str) -> UncertainDecision:
    # We cheat a bit and return UncertainDecision.DONTKNOW for both
    # verify_libc_candidate and verify_ld_candidate.
    return UncertainDecision.DONTKNOW


def verify_ld_candidate(mapping_name: str) -> UncertainDecision:
    return UncertainDecision.DONTKNOW


def urls(ver: tuple[int, ...] | None) -> LibcURLs:
    return LibcURLs(
        versioned_readable_source="",
        versioned_compressed_source="",
        homepage="",
        git="",
    )
