import types

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.gdb.events
import pwndbg.lib.memoize

try:
    from __builtins__ import reload as _reload
except Exception:
    from imp import reload as _reload


def rreload(module, mdict=None):
    """Recursively reload modules."""
    name = module.__name__

    if mdict is None:
        mdict = []

    for attribute_name in getattr(module, "__all__", []) or []:
        attribute = getattr(module, attribute_name, None)
        if isinstance(attribute, types.ModuleType) and attribute not in mdict:
            mdict.append(attribute)
            rreload(attribute, mdict)

    try:
        _reload(module)
    except Exception as e:
        pass


@pwndbg.commands.ArgparsedCommand("Reload pwndbg.")
def reload(*a):
    pwndbg.gdb.events.on_reload()
    rreload(pwndbg)
    pwndbg.gdb.events.after_reload()


@pwndbg.commands.ArgparsedCommand("Makes pwndbg reinitialize all state.")
def reinit_pwndbg():
    """
    Makes pwndbg reinitialize all state.
    """
    pwndbg.lib.memoize.reset()
    pwndbg.gdb.events.after_reload()
