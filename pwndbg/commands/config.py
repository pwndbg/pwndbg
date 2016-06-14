#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dumps all pwndbg-specific configuration points.
"""
from __future__ import unicode_literals

import pwndbg.commands
import pwndbg.config


def print_row(name, value, default, docstring):
    name = name.ljust(20)

    if value != default:
        defval  = '%s (%s)' % (value, default)
    else:
        defval = value

    defval  = defval.ljust(15)
    result = ' '.join((name, defval, docstring))
    print(result)
    return result

@pwndbg.commands.Command
def config():
    """Shows pwndbg-specific configuration points"""
    header = print_row('Name','Value', 'Def', 'Documentation')
    print('-' * (len(header)))
    for k,v in sorted(pwndbg.config.__dict__.items()):
        if not isinstance(v, pwndbg.config.Parameter):
            continue
        print_row(v.optname, repr(v.value), repr(v.default), v.docstring)
