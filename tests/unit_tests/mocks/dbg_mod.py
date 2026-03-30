from __future__ import annotations

from typing_extensions import override

import pwndbg
import pwndbg.dbg_mod
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform


class MockInferior(pwndbg.dbg_mod.Process):
    @override
    def arch(self) -> ArchDefinition:
        return ArchDefinition(name="x86-64", ptrsize=8, endian="little", platform=Platform.LINUX)


class MockDebugger(pwndbg.dbg_mod.Debugger):
    @override
    def selected_inferior(self) -> pwndbg.dbg_mod.Process:
        return MockInferior()

    @override
    def name(self) -> pwndbg.dbg_mod.DebuggerType:
        return pwndbg.dbg_mod.DebuggerType.GDB


dbg = MockDebugger()
