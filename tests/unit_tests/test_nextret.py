from __future__ import annotations

import asyncio
import sys
from unittest import mock

import pwndbg
from tests.unit_tests.mocks.dbg_mod import dbg

# Mock debugger methods required to import commands
dbg.is_gdblib_available = lambda: False
dbg.event_handler = lambda *a, **kw: lambda fn: fn
dbg.commands = list
dbg.add_command = lambda *a, **kw: None
pwndbg.dbg = dbg

# If an earlier test mocked pwndbg.commands, remove it so the package can load
old_commands = sys.modules.get("pwndbg.commands")
sys.modules.pop("pwndbg.commands", None)

import pwndbg.aglib.next
import pwndbg.commands.context
from pwndbg.commands.next import _nextret

if old_commands is not None:
    sys.modules["pwndbg.commands"] = old_commands


def test_nextret_does_not_call_context() -> None:
    with (
        mock.patch("pwndbg.aglib.next.break_next_ret", new_callable=mock.AsyncMock) as mock_break,
        mock.patch("pwndbg.commands.context.context") as mock_context,
    ):
        mock_break.return_value = True
        asyncio.run(_nextret(mock.AsyncMock()))
        mock_context.assert_not_called()
