from __future__ import annotations

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

    # Mark that we are reloading; this is used to prevent the Command decorator from
    # erroring out on re-registering the same commands we had registered before
    gdb.pwndbg_is_reloading = True
    try:
        importlib.import_module("pwndbg")
        
        # After reimporting pwndbg, we need to explicitly load commands again
        # because the setup() function is not called during module reimport
        import pwndbg.commands
        pwndbg.commands.load_commands()
    finally:
        # Always unset the reloading flag, even if an error occurs
        gdb.pwndbg_is_reloading = False


@pwndbg.commands.Command("Reload Pwndbg.", category=CommandCategory.PWNDBG)
def reload(*a) -> None:
    """
    Reload all Pwndbg modules and commands.
    
    This command performs a full reload of Pwndbg by:
    1. Disconnecting all event handlers
    2. Deleting all Pwndbg modules from memory
    3. Reimporting all modules
    4. Re-registering all commands with updated code
    5. Restoring event handlers and hooks
    
    Use this command when you have modified Pwndbg source code and want
    to see the changes without restarting GDB.
    """
    pwndbg.gdblib.events.on_reload()
    rreload(pwndbg)
    pwndbg.gdblib.events.after_reload()

    # Restore the prompt hook after reload
    # This is necessary because the old prompt_hook function was deleted during reload
    from pwndbg.gdblib import prompt
    gdb.prompt_hook = prompt.prompt_hook


@pwndbg.commands.Command("Reinitialize Pwndbg state.", category=CommandCategory.PWNDBG)
def reinit_pwndbg() -> None:
    """
    Reinitialize Pwndbg state without reloading modules.
    
    This command refreshes Pwndbg's internal state by:
    1. Clearing all caches
    2. Re-firing events to update state
    
    This is lighter weight than 'reload' and is useful when:
    - You want to reset cached values
    - The debugged process has changed state significantly
    - You want to refresh Pwndbg's view of the process
    
    Unlike 'reload', this does NOT reload source code changes.
    Use 'reload' if you have modified Pwndbg source files.
    """
    pwndbg.lib.cache.clear_caches()
    pwndbg.gdblib.events.after_reload()
