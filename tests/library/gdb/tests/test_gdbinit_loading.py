from __future__ import annotations

import pwndbg
import pwndbg.dbg_mod.gdb


def _gdb() -> pwndbg.dbg_mod.gdb.GDB:
    assert isinstance(pwndbg.dbg, pwndbg.dbg_mod.gdb.GDB)
    return pwndbg.dbg


def test_gdbinit_not_loaded_again_when_sourced(monkeypatch):
    # With `source /path/to/gdbinit.py`, GDB has already handled .gdbinit files
    # (and `--nx`/`--nh`), so Pwndbg must not load them again.
    monkeypatch.setattr(pwndbg, "_is_portable", False)
    assert _gdb()._disable_gdbinit_loading() == (True, True)


def test_gdbinit_loading_in_portable_mode(monkeypatch):
    # The tests run GDB as `pwndbg --silent --nx`: the launcher's own `-nx`
    # plus the user's `--nx`, so Pwndbg must not load any .gdbinit file.
    monkeypatch.setattr(pwndbg, "_is_portable", True)
    disable_any, _ = _gdb()._disable_gdbinit_loading()
    assert disable_any is True
