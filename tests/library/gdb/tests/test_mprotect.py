from __future__ import annotations

import gdb


def test_cannot_run_mprotect_when_not_running(start_binary):
    # expect error message
    assert "mprotect: The program is not being run.\n" == gdb.execute(
        "mprotect 0x0 0x1000 PROT_EXEC|PROT_READ|PROT_WRITE", to_string=True
    )
