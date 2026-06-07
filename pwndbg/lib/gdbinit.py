"""Small helpers for figuring out whether we should skip loading gdbinit files.

Kept dependency-free so it can be unit tested without dragging in the real gdb
module.
"""

from __future__ import annotations


def disable_gdbinit_loading(cmdline: list[str], loaded_from_portable: bool) -> tuple[bool, bool]:
    """Mirror gdb's --nx/--nh handling, accounting for the portable launcher.

    Returns (disable_any, disable_home). cmdline is the process argv, and
    loaded_from_portable says whether we got here through the portable `pwndbg`
    binary (which injects its own -nx) instead of being sourced from a user's
    own .gdbinit.
    """
    disable_home_gdbinit = 0
    disable_any_gdbinit = 0
    for arg in cmdline:
        if arg in ("-args", "--args"):
            break
        if arg in ("-nh", "--nh"):
            disable_home_gdbinit += 1
        elif arg in ("-nx", "--nx", "-n", "--n"):
            disable_any_gdbinit += 1

    if disable_any_gdbinit == 0:
        # The `--nx` option is added only in pwndbg-portable mode.
        # This keeps the OLD syntax working, eg: `source /path/to/pwndbg/gdbinit.py` from ~/.gdbinit
        return True, True

    # The portable binary injects one -nx of its own, so the user's real --nx only
    # starts counting from the second one. When we were sourced from a user's
    # .gdbinit there's no injected -nx, so a single --nx is enough, same as vanilla gdb.
    nx_threshold = 2 if loaded_from_portable else 1
    return disable_any_gdbinit >= nx_threshold, disable_home_gdbinit >= 1
