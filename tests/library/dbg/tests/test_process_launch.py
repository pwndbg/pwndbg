from __future__ import annotations

from pathlib import Path

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import get_expr
from . import pwndbg_test


@pwndbg_test
async def test_process_launch_stdin(ctrl: Controller, tmp_path: Path) -> None:
    input_file = tmp_path / "stdin.txt"
    input_file.write_text("1337\n", encoding="utf-8")

    await ctrl.launch(get_binary("stdin.native.out"), stdin=input_file)
    break_at_sym("break_here")
    await ctrl.cont()

    assert int(get_expr("stdin_value")) == 1337


@pwndbg_test
async def test_process_launch_recovers_from_invalid_stdin(ctrl: Controller, tmp_path: Path) -> None:
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.LLDB:
        pytest.skip("LLDB process-driver regression test")

    binary = get_binary("stdin.native.out")

    await ctrl.launch(binary, stdin=tmp_path / "does-not-exist.txt")

    input_file = tmp_path / "stdin.txt"
    input_file.write_text("1337\n", encoding="utf-8")
    await ctrl.launch(binary, stdin=input_file)
    break_at_sym("break_here")
    await ctrl.cont()

    assert int(get_expr("stdin_value")) == 1337
