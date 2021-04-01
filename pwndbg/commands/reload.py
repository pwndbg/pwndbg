#!/usr/bin/env python
# -*- coding: utf-8 -*-

import types

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.events
import pwndbg.memoize

try:
    from __builtins__ import reload as _reload
except:
    from imp import reload as _reload



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
        pass


@pwndbg.commands.ArgparsedCommand("Reload pwndbg.")
def reload(*a):
    pwndbg.events.on_reload()
    rreload(pwndbg)
    pwndbg.events.after_reload()

@pwndbg.commands.ArgparsedCommand("Makes pwndbg reinitialize all state.")
def reinit_pwndbg():
    """
    Makes pwndbg reinitialize all state.
    """
    pwndbg.memoize.reset()
    pwndbg.events.after_reload()
