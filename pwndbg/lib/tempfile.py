"""
Common helper and cache for pwndbg tempdir
"""

from __future__ import annotations

import os
import tempfile

import pwndbg.lib.cache


@pwndbg.lib.cache.cache_until("forever")
def tempdir() -> str:
    """
    Returns a safe and unpredictable temporary directory with pwndbg prefix.
    """
    return tempfile.mkdtemp(prefix="pwndbg-")


@pwndbg.lib.cache.cache_until("forever")
def cachedir(namespace: str | None = None) -> str:
    """
    Returns and potentially creates a persistent safe cachedir location
    based on XDG_CACHE_HOME or ~/.cache

    Optionally creates a sub namespace inside the pwndbg cache folder.
    """
    cachehome = os.getenv("XDG_CACHE_HOME") or os.path.join(os.getenv("HOME", ""), ".cache")
    cachedir = os.path.join(cachehome, "pwndbg")
    if namespace:
        cachedir = os.path.join(cachedir, namespace)
    os.makedirs(cachedir, exist_ok=True)
    return cachedir
