import __builtin__
import imp
import os
import sys
import types
import gdb
import pwndbg.commands
import pwndbg

_reload = __builtin__.reload
def rreload(module, paths=[''], mdict=None):
    """Recursively reload modules."""
    name = module.__name__

    if mdict is None:
        mdict = {}

    if module not in mdict:
        mdict[module] = []

    _reload(module)

    for attribute_name in dir(module):
        attribute = getattr(module, attribute_name)

        if attribute_name == 'inthook':             continue
        if type(attribute) is not types.ModuleType: continue
        if not attribute.__name__.startswith(name): continue
        if attribute in mdict[module]:              continue

        mdict[module].append(attribute)
        rreload(attribute, paths, mdict)

    _reload(module)

    # Need to re-fire all events

@pwndbg.commands.Command
def reload(*a):
    rreload(pwndbg)

