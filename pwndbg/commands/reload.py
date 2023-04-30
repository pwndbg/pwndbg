import importlib
import sys

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.gdblib.events
import pwndbg.lib.cache
from pwndbg.commands import CommandCategory


def rreload(module, _exclude_mods=None) -> None:
    """Recursively reload modules.
    Impl based on https://stackoverflow.com/a/66661311/1508881"""
    for module in list(sys.modules.keys()):
        if "pwndbg" in module:
            del sys.modules[module]

    # Mark that we are reloading; this is used to prevent ArgparsedCommand from
    # erroring out on re-registering the same commands we had registered before
    gdb.pwndbg_is_reloading = True
    importlib.import_module("pwndbg")


@pwndbg.commands.ArgparsedCommand("Reload pwndbg.", category=CommandCategory.PWNDBG)
def reload(*a) -> None:
    pwndbg.gdblib.events.on_reload()
    rreload(pwndbg)
    pwndbg.gdblib.events.after_reload()


@pwndbg.commands.ArgparsedCommand(
    "Makes pwndbg reinitialize all state.", category=CommandCategory.PWNDBG
)
def reinit_pwndbg() -> None:
    """
    Makes pwndbg reinitialize all state.
    """
    pwndbg.lib.cache.clear_caches()
    pwndbg.gdblib.events.after_reload()
