from __future__ import annotations

from pwndbg.lib.gdbinit import disable_gdbinit_loading


def test_portable_needs_two_nx_to_disable():
    # one user --nx is not enough under the portable binary because the launcher
    # already injected its own -nx.
    disable_any, _ = disable_gdbinit_loading(["gdb", "-q", "-nx"], loaded_from_portable=True)
    assert disable_any is False

    disable_any, _ = disable_gdbinit_loading(["gdb", "-q", "-nx", "-nx"], loaded_from_portable=True)
    assert disable_any is True


def test_sourced_needs_one_nx_to_disable():
    # when sourced from a user's own .gdbinit a single --nx should disable loading,
    # matching vanilla gdb. this is the actual bug from #3896.
    disable_any, _ = disable_gdbinit_loading(
        ["gdb", "-nx", "-x", "~/.gdbinit.local"], loaded_from_portable=False
    )
    assert disable_any is True


def test_no_nx_keeps_old_source_syntax_working():
    # no --nx at all still disables everything, so the old `source gdbinit.py` style
    # from ~/.gdbinit keeps working.
    disable_any, disable_home = disable_gdbinit_loading(["gdb"], loaded_from_portable=False)
    assert disable_any is True
    assert disable_home is True


def test_nh_disables_home():
    _, disable_home = disable_gdbinit_loading(["gdb", "-nx", "-nh"], loaded_from_portable=False)
    assert disable_home is True


def test_args_stops_counting():
    # flags after --args belong to the debugged program, so they don't count as
    # user --nx. with none counted we fall back to disabling (old source syntax).
    disable_any, disable_home = disable_gdbinit_loading(
        ["gdb", "--args", "./prog", "-nx", "-nx"], loaded_from_portable=True
    )
    assert disable_any is True
    assert disable_home is True
