from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import gdb


@contextmanager
def lock_scheduler() -> Iterator[None]:
    """
    This context manager can be used to run GDB commands with threads scheduling
    being locked which means that other threads will be stopped during execution.

    This is useful to prevent bugs where e.g.: gdb.parse_and_eval("(int)foo()")
    would execute foo() on the current debugee thread but would also unlock other
    threads for being executed and those other threads may for example hit a
    breakpoint we set previously which would be confusing for the user.

    See also: https://sourceware.org/gdb/onlinedocs/gdb/All_002dStop-Mode.html
    """
    old_config = gdb.parameter("scheduler-locking")
    if old_config != "on":
        gdb.execute("set scheduler-locking on")
        yield
        gdb.execute(f"set scheduler-locking {old_config}")
    else:
        yield


def parse_and_eval_with_scheduler_lock(expr: str) -> gdb.Value:
    with lock_scheduler():
        return gdb.parse_and_eval(expr)
