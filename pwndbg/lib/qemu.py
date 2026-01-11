"""
QEMU-related utility functions.
"""

from __future__ import annotations

import re

_QEMU_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_qgdbserverversion(response: bytes) -> tuple[int, ...] | None:
    """
    Parse the response from qGDBServerVersion packet and extract version tuple.

    Args:
        response: Raw bytes response from the qGDBServerVersion packet

    Returns:
        Tuple of version integers (e.g., (10, 1, 0)) or None if parsing fails
    """
    if not response or response.startswith(b"E"):
        return None

    text = response.decode(errors="ignore").strip()
    if not text:
        return None

    match = _QEMU_VERSION_RE.search(text)
    if not match:
        return None

    return tuple(int(part) for part in match.groups() if part is not None)
