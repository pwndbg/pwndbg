from __future__ import annotations

from elftools.elf.relocation import Relocation

from . import common
from .api import LibcType


def type() -> LibcType:
    return LibcType.GLIBC


def is_being_used() -> bool:
    return True


def initialize() -> bool:
    return True


def version() -> tuple[int, ...]:
    return (1, 1)


def has_symbols() -> bool:
    return True


def has_debug_info() -> bool:
    return True


def filename() -> str:
    return ""


def loader_filename() -> str:
    return ""


def mapping() -> str:
    return ""


def loader_mapping() -> str:
    return ""


def relocations_by_section_name(section_name: str) -> tuple[Relocation, ...]:
    return common.relocations_by_section_name(section_name, filename())


def section_address_by_name(section_name: str) -> int:
    return common.section_address_by_name(section_name, filename())


def source_url() -> str:
    ver = version()
    ver_str = ".".join(map(str, ver))
    return f"https://elixir.bootlin.com/glibc/glibc-{ver_str}/source"
