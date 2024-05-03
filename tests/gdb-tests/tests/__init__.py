from __future__ import annotations

import functools

import gdb

import tests

from . import binaries


def start_and_break_on(binary, bps, *args):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            path = binaries.get(binary)

            gdb.execute("file " + path)
            gdb.execute("set exception-verbose on")
            gdb.execute("starti " + " ".join(args))

            if bps is not None and len(bps) > 0:
                for bp in bps:
                    gdb.execute(f"break {bp}")
                gdb.execute("continue")

            return func(*args, **kwargs)

        return wrapper

    return decorator
