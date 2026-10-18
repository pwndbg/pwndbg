from __future__ import annotations

import re
import sys

import pwndbg
import pwndbg.commands
import pwndbg.gdblib.events
import pwndbg.lib.cache
from pwndbg.commands import CommandCategory
from pwndbg.dbg_mod import DebuggerType
from pwndbginit import set_reloading_status
from pwndbginit.gdbinit import main_try


def rreload() -> None:
    """Recursively reload modules.
    Impl based on https://stackoverflow.com/a/66661311/1508881"""
    pattern = re.compile(r"^pwndbg(\..+)?$")
    for module in list(sys.modules.keys()):
        if pattern.match(module):
            del sys.modules[module]

    # Mark that we are reloading; this is used to prevent the Command decorator from
    # erroring out on re-registering the same commands we had registered before
    set_reloading_status(True)
    main_try()


@pwndbg.commands.Command(
    "Reload Pwndbg.", category=CommandCategory.DEV, only_debuggers={DebuggerType.GDB}
)
def reload() -> None:
    pwndbg.gdblib.events.on_reload()
    rreload()
    pwndbg.gdblib.events.after_reload()


@pwndbg.commands.Command("Makes Pwndbg reinitialize all state.", category=CommandCategory.DEV)
def reinit_pwndbg() -> None:
    """
    Makes pwndbg reinitialize all state.
    """
    pwndbg.lib.cache.clear_caches()
    pwndbg.gdblib.events.after_reload()
