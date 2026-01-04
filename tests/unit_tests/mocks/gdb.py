from __future__ import annotations

import sys
from unittest.mock import MagicMock

module_name = "gdb"
module = MagicMock()
sys.modules[module_name] = module

import gdb

gdb.PARAM_BOOLEAN = 0
gdb.PARAM_ZINTEGER = 4
gdb.PARAM_STRING = 8

gdb.VERSION = "8.3.1"
