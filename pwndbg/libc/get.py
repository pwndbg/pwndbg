from __future__ import annotations

from .api import Libc


def get_libc() -> Libc:
    from . import glibc

    if glibc.is_being_used():
        glibc.initialize()
        return glibc

    from . import musl

    if musl.is_being_used():
        musl.initialize()
        return musl

    from . import unknown

    assert unknown.is_being_used()
    unknown.initialize()
    return unknown
