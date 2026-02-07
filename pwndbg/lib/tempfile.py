"""
Common helper and cache for pwndbg tempdir
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pwndbg.lib.cache


@pwndbg.lib.cache.cache_until("forever")
def tempdir() -> Path:
    """
    Returns a safe and unpredictable temporary directory with pwndbg prefix.
    """
    return Path(tempfile.mkdtemp(prefix="pwndbg-"))


@pwndbg.lib.cache.cache_until("forever")
def cachedir(namespace: str | None = None) -> Path:
    """
    Returns and potentially creates a persistent safe cachedir location
    based on XDG_CACHE_HOME or ~/.cache or LOCALAPPDATA (Windows)

    Optionally creates a sub namespace inside the pwndbg cache folder.
    """
    if sys.platform == "win32":
        cachehome = os.getenv("LOCALAPPDATA")
    else:
        cachehome = os.getenv("XDG_CACHE_HOME") or os.path.join(os.getenv("HOME", ""), ".cache")
    cachedir = os.path.join(cachehome or tempfile.gettempdir(), "pwndbg")
    if namespace:
        cachedir = os.path.join(cachedir, namespace)
    os.makedirs(cachedir, exist_ok=True)
    return Path(cachedir)
