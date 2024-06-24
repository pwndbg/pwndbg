from __future__ import annotations

from typing import Any
from typing import Tuple

import lldb
from typing_extensions import override

import pwndbg


class LLDB(pwndbg.dbg_mod.Debugger):
    @override
    def setup(self, *args):
        debugger = args[0]
        assert (
            debugger.__class__ is lldb.SBDebugger
        ), "lldbinit.py should call setup() with an lldb.SBDebugger object"

        self.debugger = debugger

    @override
    def get_cmd_window_size(self) -> Tuple[int, int]:
        import pwndbg.ui

        return pwndbg.ui.get_window_size()

    @override
    def addrsz(self, address: Any) -> str:
        return "%#16x" % address

    @override
    def set_python_diagnostics(self, enabled: bool) -> None:
        pass
