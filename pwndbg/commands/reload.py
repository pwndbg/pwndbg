import types
from imp import reload as _reload

import pwndbg
import pwndbg.commands
import pwndbg.gdblib.events
import pwndbg.lib.memoize


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
    pwndbg.gdblib.events.on_reload()
    rreload(pwndbg)
    pwndbg.gdblib.events.after_reload()


@pwndbg.commands.ArgparsedCommand("Makes pwndbg reinitialize all state.")
def reinit_pwndbg():
    """
    Makes pwndbg reinitialize all state.
    """
    pwndbg.lib.memoize.reset()
    pwndbg.gdblib.events.after_reload()
