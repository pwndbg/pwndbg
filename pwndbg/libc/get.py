from __future__ import annotations

from .api import Libc


def get() -> Libc:
    from . import glibc

    if glibc._is_being_used():
        return glibc

    from . import musl

    if musl._is_being_used():
        return musl

    from . import unknown

    assert unknown._is_being_used()
    return unknown
