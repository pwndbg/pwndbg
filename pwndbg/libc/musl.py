from __future__ import annotations

from pathlib import Path

from elftools.elf.relocation import Relocation

from . import common
from .api import LibcType
from .api import LibcURLs


def type() -> LibcType:
    return LibcType.MUSL


def _is_being_used() -> bool:
    # TODO
    # Check if the string "/tmp/tmpnam_XXXX" is in the .rodata of the binary.
    # Added in musl version v1.1.2 (is present until at least v1.2.5).
    # https://elixir.bootlin.com/musl/v1.1.2/source/src/stdio/tmpnam.c#L15
    return True


def version() -> tuple[int, ...]:
    return (1, 1)


def has_symbols() -> bool:
    return True


def has_debug_info() -> bool:
    return True


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
    # FIXME: Can we get the version somehow?
    return LibcURLs(
        versioned_readable_source="https://elixir.bootlin.com/musl/latest/source",
        versioned_compressed_source="https://musl.libc.org/releases/musl-1.2.5.tar.gz",
        homepage="https://musl.libc.org/",
        git="git://git.musl-libc.org/musl",
    )
