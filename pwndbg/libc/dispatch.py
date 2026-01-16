from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from pwndbg.lib.common import UncertainDecision


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


class LibcWrangler(Protocol):
    """
    Libc implementations must conform to this protocol in order to be properly used by the facade.
    """

    def type(self) -> LibcType:
        """
        Which libc implementation is currently active?
        """
        ...

    def version(self, libc_filepath: str) -> tuple[int, ...]:
        """
        Get the version of the libc implementation as a tuple.

        If the implementation cannot recover the version, it returns
        (-1, -1).
        """
        ...

    def has_internal_symbols(self, libc_filepath: str) -> bool:
        """
        Do we have internal library symbols?

        If the library is dynamically linked, even if it is stripped it will retain its
        exported symbols (e.g. fscanf) because they are required for dynamic linking.

        This funcions checks if the non-exported symbols (like __GI_exit, __run_exit_handlers,
        intitial) are also available.

        Symbols are global variables and functions. Internal symbols also come with debug info.
        """
        ...

    def has_debug_info(self) -> bool:
        """
        Do we have debugging information like structure types?
        """
        ...

    def urls(self, ver: tuple[int, ...] | None) -> LibcURLs:
        """
        Get useful URLs regarding this libc implementation.

        `ver` is the version tuple. If a libc implements the version() function
        it must `assert ver is not None`, otherwise it must `assert ver is None`.
        """
        ...

    def verify_libc_candidate(self, mapping_name: str) -> UncertainDecision:
        """
        Verify whether the mapping with the provided name is implementing
        this specific libc.

        This must be accurate enough that no other libc implementation will
        provide a conflicting answer.

        A libc implementation must implement at least one of verify_libc_candidate
        and verify_ld_candidate. The other may simply return UncertainDecision.DONTKNOW.
        """
        ...

    def verify_ld_candidate(self, mapping_name: str) -> UncertainDecision:
        """
        Verify whether the mapping with the provided name is implementing
        this specific libc's loader.

        This must be accurate enough that no other libc implementation will
        provide a conflicting answer.

        A libc implementation must implement at least one of verify_libc_candidate
        and verify_ld_candidate. The other may simply return UncertainDecision.DONTKNOW.
        """
        ...

    def libc_same_as_ld(self) -> bool:
        """
        Returns whether the libc and the ld are loaded as one object file for this libc
        implementation.
        """
        ...
