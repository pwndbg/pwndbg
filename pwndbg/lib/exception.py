from __future__ import annotations

from types import TracebackType
from typing import Optional
from typing import Type

import pwndbg.color as C


class IndentContextManager:
    def __init__(self) -> None:
        self.indent = 0

    def __enter__(self) -> None:
        self.indent += 1

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.indent -= 1
        assert self.indent >= 0

    def print(self, *a, **kw) -> None:
        print("    " * self.indent, *a, **kw)

    def addr_hex(self, val: int) -> str:
        return C.yellow(hex(val))

    def aux_hex(self, val: int) -> str:
        return C.red(hex(val))

    def prefix(self, s: str):
        if self.indent % 2 == 0:
            return C.blue(s)
        return C.green(s)
