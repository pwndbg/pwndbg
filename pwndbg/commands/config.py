#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dumps all pwndbg-specific configuration points.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.commands
import pwndbg.config
from pwndbg.color import ljust_colored
from pwndbg.color import strip


def print_row(name, value, default, docstring, ljust_optname, ljust_value, empty_space=6):
    name = ljust_colored(name, ljust_optname + empty_space)
    defval = extend_value_with_default(value, default)
    defval = ljust_colored(defval, ljust_value + empty_space)
    result = ' '.join((name, defval, docstring))
    print(result)
    return result

def extend_value_with_default(value, default):
    if strip(value) != strip(default):
        return '%s (%s)' % (value, default)
    return value

@pwndbg.commands.Command
def config():
    """Shows pwndbg-specific configuration points"""

    values = [v for k, v in pwndbg.config.__dict__.items()
              if isinstance(v, pwndbg.config.Parameter) and v.scope == 'config']
    longest_optname = max(map(len, [v.optname for v in values]))
    longest_value = max(map(len, [extend_value_with_default(repr(v.value), repr(v.default)) for v in values]))

    header = print_row('Name', 'Value', 'Def', 'Documentation', longest_optname, longest_value)
    print('-' * (len(header)))

    for v in sorted(values):
        print_row(v.optname, repr(v.value), repr(v.default), v.docstring, longest_optname, longest_value)
