from __future__ import annotations

import gdb


def test_command_procinfo_before_binary_start():
    result = gdb.execute("procinfo", to_string=True)
    assert "The program is not being run" in result
