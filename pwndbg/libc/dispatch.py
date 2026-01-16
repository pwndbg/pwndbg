from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


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

    def verify_libc_candidate(self, mapping_name: str) -> bool:
        """
        Verify whether the mapping with the provided name is implementing
        this specific libc.
        """
        ...

    def verify_ld_candidate(self, mapping_name: str) -> bool:
        """
        Verify whether the mapping with the provided name is implementing
        this specific libc's loader.
        """
        ...

