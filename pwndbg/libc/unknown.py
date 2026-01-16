from __future__ import annotations

from pathlib import Path

from elftools.elf.relocation import Relocation

from .dispatch import LibcType
from .dispatch import LibcURLs


def type() -> LibcType:
    return LibcType.UNKNOWN


def _is_being_used() -> bool:
    return True


def version() -> tuple[int, ...]:
    raise NotImplementedError


def has_symbols() -> bool:
    return False


def has_debug_info() -> bool:
    return False


def verify_libc_candidate(mapping_name: str) -> bool:
    return True


def verify_ld_candidate(mapping_name: str) -> bool:
    return True


def urls() -> LibcURLs:
    return LibcURLs(
        versioned_readable_source="",
        versioned_compressed_source="",
        homepage="",
        git="",
    )
