import __builtin__
import imp
import os
import sys
import types
import gdb
import pwndbg.events
import pwndbg.commands
import pwndbg

_reload = __builtin__.reload
def rreload(module, mdict=None):
    """Recursively reload modules."""
    name = module.__name__

    if mdict is None:
        mdict = []

    for attribute_name in getattr(module, '__all__', []) or []:
        attribute = getattr(module, attribute_name, None)
        if isinstance(attribute, types.ModuleType) and attribute not in mdict:
            mdict.append(attribute)
            rreload(attribute, mdict)

    try:
        _reload(module)
    except Exception as e:
        print e
        pass


@pwndbg.commands.Command
def reload(*a):
    print "BYTE"
    pwndbg.events.on_reload()
    rreload(pwndbg)
    pwndbg.events.after_reload()

