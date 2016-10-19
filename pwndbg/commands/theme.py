#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dumps all pwndbg-specific theme configuration points.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.color.theme
import pwndbg.commands
import pwndbg.config
from pwndbg.color import generateColorFunction
from pwndbg.commands.config import extend_value_with_default
from pwndbg.commands.config import print_row


@pwndbg.commands.Command
def theme():
    """Shows pwndbg-specific theme configuration points"""
    values = [v for k, v in pwndbg.config.__dict__.items()
              if isinstance(v, pwndbg.config.Parameter) and v.scope == 'theme']
    longest_optname = max(map(len, [v.optname for v in values]))
    longest_value = max(map(len, [extend_value_with_default(str(v.value), str(v.default)) for v in values]))

    header = print_row('Name', 'Value', 'Def', 'Documentation', longest_optname, longest_value)
    print('-' * (len(header)))
    for v in sorted(values):
        if isinstance(v, pwndbg.color.theme.ColoredParameter):
            value = generateColorFunction(v.value)(v.value)
            default = generateColorFunction(v.default)(v.default)
        elif isinstance(v.value, str):
            value = "'%s'" % str(v.value)
            default = str(v.default)
        else:
            value = repr(v.value)
            default = repr(v.default)
        print_row(v.optname, value, default, v.docstring, longest_optname, longest_value)
