from __future__ import annotations

from typing import Literal

from typing_extensions import override

import pwndbg


class MockArch(pwndbg.dbg_mod.Arch):
    @override
    def ptrsize(self) -> int:
        return 8

    @override
    def arch(self) -> str:
        return "x86-64"

    @override
    def endian(self) -> Literal["little", "big"]:
        return "little"


class MockInferior(pwndbg.dbg_mod.Process):
    @override
    def arch(self) -> dbg_mod.Arch:
        return MockArch()


class MockDebugger(pwndbg.dbg_mod.Debugger):
    @override
    def selected_inferior(self) -> dbg_mod.Process:
        return MockInferior()


pwndbg.dbg = MockDebugger()
