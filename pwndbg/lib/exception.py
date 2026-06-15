from __future__ import annotations

from types import TracebackType

from pwndbg import color


class IndentContextManager:
    def __init__(self) -> None:
        self.indent = 0

    def __enter__(self) -> None:
        self.indent += 1

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.indent -= 1
        assert self.indent >= 0

    def print(self, *a, **kw) -> None:
        print("    " * self.indent, *a, **kw)

    def addr_hex(self, val: int) -> str:
        return color.yellow(hex(val))

    def aux_hex(self, val: int) -> str:
        return color.red(hex(val))

    def prefix(self, s: str):
        if self.indent % 2 == 0:
            return color.blue(s)
        return color.green(s)
