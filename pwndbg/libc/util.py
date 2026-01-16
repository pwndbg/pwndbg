from __future__ import annotations


def version_parse(data: bytearray) -> tuple[int, ...]:
    """
    Parse the version bytestring as read from memory into
    an integer tuple.
    """
    # Example from compiled musl: 1.2.5-git-103-g7bcf8783
    data = data.split(b"-")[0]
    return tuple(int(part) for part in data.split(b"."))
