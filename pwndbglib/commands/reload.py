#!/usr/bin/env python
# -*- coding: utf-8 -*-

import types

import gdb

import pwndbglib
import pwndbglib.commands
import pwndbglib.events
import pwndbglib.memoize

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


@pwndbglib.commands.ArgparsedCommand("Reload pwndbg.")
def reload(*a):
    pwndbglib.events.on_reload()
    rreload(pwndbglib)
    pwndbglib.events.after_reload()

@pwndbglib.commands.ArgparsedCommand("Makes pwndbg reinitialize all state.")
def reinit_pwndbg():
    """
    Makes pwndbg reinitialize all state.
    """
    pwndbglib.memoize.reset()
    pwndbglib.events.after_reload()
