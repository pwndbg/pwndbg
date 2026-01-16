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
    def type(self) -> LibcType:
        """
        Which libc implementation is currently active?
        """
        ...

    def version(self) -> tuple[int, ...]:
        """
        Get the version of the libc implementation as a tuple.

        This shouldn't be put behind the facade because you should
        only care about the libc version if you know which libc
        you are using.

        It may not always be possible to implement this, in which case
        this raises a NotImplementedError.
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

    def urls(self) -> LibcURLs:
        """
        Get useful URLs regarding this libc implementation.
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
