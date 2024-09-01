from __future__ import annotations

import sys


def system_decode(b: bytes) -> str:
    """
    LLDB requires Python strings in many places where it makes sense to accept
    bytes values. This is mostly an artifact of how Swig maps C `char*` to
    `str` in Python, but since Swig will refuse bytes objects, we have to figure
    out a way to pass this data as a regular string object, even if that's
    nonsensical in Python terms.

    This function tries its best to resolve that by decoding it with the same
    decoder the filesystem uses, and, failing that, ASCII.
    """

    native = sys.getfilesystemencoding()

    try:
        return b.decode(native)
    except UnicodeDecodeError:
        pass

    return b.decode("ascii")
