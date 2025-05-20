from __future__ import annotations

from typing_extensions import override

import pwndbg
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform


class MockInferior(pwndbg.dbg_mod.Process):
    @override
    def arch(self) -> ArchDefinition:
        return ArchDefinition(name="x86-64", ptrsize=8, endian="little", platform=Platform.LINUX)


class MockDebugger(pwndbg.dbg_mod.Debugger):
    @override
    def selected_inferior(self) -> dbg_mod.Process:
        return MockInferior()


pwndbg.dbg = MockDebugger()
