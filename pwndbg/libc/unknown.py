from __future__ import annotations

from pathlib import Path

from elftools.elf.relocation import Relocation

from . import common
from .api import LibcType
from .api import LibcURLs


def type() -> LibcType:
    return LibcType.UNKNOWN


def _is_being_used() -> bool:
    return True


def version() -> tuple[int, ...]:
    return (0, 0)


def has_symbols() -> bool:
    return False


def has_debug_info() -> bool:
    return False


def filepath() -> Path:
    return Path("")


def loader_filepath() -> Path:
    return Path("")


def addr() -> int:
    return 0


def loader_addr() -> int:
    return 0


def section_by_name(section_name: str) -> tuple[int, int, bytes] | None:
    return common.section_by_name(section_name, filepath())


def section_address_by_name(section_name: str) -> int:
    return common.section_address_by_name(section_name, filepath())


def relocations_by_section_name(section_name: str) -> tuple[Relocation, ...]:
    return common.relocations_by_section_name(section_name, filepath())


def urls() -> LibcURLs:
    return LibcURLs(
        versioned_readable_source="",
        versioned_compressed_source="",
        homepage="",
        git="",
    )
