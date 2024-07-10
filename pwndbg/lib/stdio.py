"""
Provides functionality to circumvent GDB's hooks on sys.stdin and sys.stdout
which prevent output from appearing on-screen inside of certain event handlers.
"""

from __future__ import annotations

import sys
from types import TracebackType
from typing import Any
from typing import List
from typing import TextIO
from typing import Tuple
from typing import Type


class Stdio:
    queue: List[Tuple[TextIO, TextIO, TextIO]] = []

    def __enter__(self, *a: Any, **kw: Any) -> None:
        self.queue.append((sys.stdin, sys.stdout, sys.stderr))

        sys.stdin = sys.__stdin__
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        sys.stdin, sys.stdout, sys.stderr = self.queue.pop()


stdio = Stdio()
