from __future__ import annotations

import pwndbg.lib.config

config: pwndbg.lib.config.Config = pwndbg.lib.config.Config()
"""
The global configuration object.
"""

import pwndbg.color
import pwndbg.exception
import pwndbg.lib.version
import pwndbg.ui
from pwndbg.dbg_mod import dbg as dbg

__version__ = pwndbg.lib.version.__version__
"""Pwndbg version."""
version = __version__
"""Pwndbg version."""

# Don't know where else to put this xd
config.add_param("dev-debug-events", False, "display internal event debugging info")
