from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

from elftools.elf.relocation import Relocation


class LibcType(Enum):
    GLIBC = "glibc"
    MUSL = "musl"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LibcURLs:
    versioned_readable_source: str
    versioned_compressed_source: str
    homepage: str
    git: str


class Libc(Protocol):
    def type(self) -> LibcType:
        """
        Which libc implementation is currently active?
        """
        ...

    def _is_being_used(self) -> bool:
        """
        Libc's need to implement this to identify whether they are
        the ones the debugee is using.

        If an implementation can't see any symbols and can't perform the check without
        them, it should return False.

        This is used to dispatch to the correct libc implementation, you shouldn't
        use this.

        If you want to check whether a specific libc implementation is active,
        do this: pwndbg.libc.get().type() == pwndbg.libc.LibcType.GLIBC .
        """
        ...

    def version(self) -> tuple[int, ...]:
        """
        Get the version of the libc implementation as a tuple.
        """
        ...

    def has_symbols(self) -> bool:
        """
        Can we read out global variables and functions in the libc object file?
        """
        ...

    def has_debug_info(self) -> bool:
        """
        Do we have debugging information like structure types?
        """
        ...

    def filepath(self) -> Path:
        """
        The filepath of the libc shared object.

        There may not be a backing file for this Path if we are remote debugging.
        This may have the same value as loader_filepath() for some libc's.
        """
        ...

    def loader_filepath(self) -> Path:
        """
        The filepath of the ld shared object.

        There may not be a backing file for this Path if we are remote debugging.
        This may have the same value as filepath() for some libc's.
        """
        ...

    def addr(self) -> int:
        """
        The start load address of the libc shared object file.

        May be the same as loader_addr() for some libc's.
        """
        ...

    def loader_addr(self) -> int:
        """
        The start load address of the ld shared object file.

        May be the same as addr() for some libc's.
        """
        ...

    def section_by_name(self, section_name: str) -> tuple[int, int, bytes] | None:
        """
        Returns pwndbg.aglib.elf.section_by_name() for the libc shared object file.
        """
        ...

    def section_address_by_name(self, section_name: str) -> int:
        """
        Get the start load address of the section `section_name` in the libc shared
        object file.
        """
        ...

    def relocations_by_section_name(self, section_name: str) -> tuple[Relocation, ...]:
        """
        Returns pwndbg.aglib.elf.relocations_by_section_name() for the libc shared object file.
        """
        ...

    def urls(self) -> LibcURLs:
        """
        Get useful URLs regarding this libc implementation.
        """
        ...
