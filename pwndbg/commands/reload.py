#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import types

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


@pwndbg.commands.Command
def reload(*a):
    pwndbg.events.on_reload()
    rreload(pwndbg)
    pwndbg.events.after_reload()


@pwndbg.commands.Command
def reinit_pwndbg():
    """
    Makes pwndbg reinitialize all state.
    """
    pwndbg.memoize.reset()
    pwndbg.events.after_reload()
