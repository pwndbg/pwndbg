"""
Common helper and cache for pwndbg tempdir
"""

import os
import tempfile

import pwndbg.lib.memoize


@pwndbg.lib.memoize.forever
def tempdir():
    """
    Returns a safe and unpredictable temporary directory with pwndbg prefix.
    """
    return tempfile.mkdtemp(prefix="pwndbg-")


@pwndbg.lib.memoize.forever
def cachedir(namespace=None):
    """
    Returns and potentially creates a persistent safe cachedir location
    based on XDG_CACHE_HOME or ~/.cache

    Optionally creates a sub namespace inside the pwndbg cache folder.
    """
    cachehome = os.getenv("XDG_CACHE_HOME")
    if not cachehome:
        cachehome = os.path.join(os.getenv("HOME"), ".cache")
    cachedir = os.path.join(cachehome, "pwndbg")
    if namespace:
        cachedir = os.path.join(cachedir, namespace)
    os.makedirs(cachedir, exist_ok=True)
    return cachedir
