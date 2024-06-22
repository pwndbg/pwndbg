from __future__ import annotations

# isort: off
import pwndbg.lib.config

config: pwndbg.lib.config.Config = pwndbg.lib.config.Config()
# isort: on

import pwndbg.color
import pwndbg.exception
import pwndbg.lib.version
import pwndbg.ui
from pwndbg import dbg as dbg_mod
from pwndbg.dbg import dbg as dbg

__version__ = pwndbg.lib.version.__version__
version = __version__
