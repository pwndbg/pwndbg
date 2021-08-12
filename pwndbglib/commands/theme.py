#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dumps all pwndbg-specific theme configuration points.
"""

import argparse

import pwndbglib.color.theme
import pwndbglib.commands
import pwndbglib.config
from pwndbglib.color import generateColorFunction
from pwndbglib.color.message import hint
from pwndbglib.commands.config import extend_value_with_default
from pwndbglib.commands.config import get_config_parameters
from pwndbglib.commands.config import print_row

parser = argparse.ArgumentParser(description='Shows pwndbg-specific theme config. The list can be filtered.')
parser.add_argument('filter_pattern', type=str, nargs='?', default=None,
                    help='Filter to apply to theme parameters names/descriptions')


@pwndbglib.commands.ArgparsedCommand(parser)
def theme(filter_pattern):
    values = get_config_parameters('theme', filter_pattern)

    if not values:
        print(hint('No theme parameter found with filter "{}"'.format(filter_pattern)))
        return

    longest_optname = max(map(len, [v.optname for v in values]))
    longest_value = max(map(len, [extend_value_with_default(str(v.value), str(v.default)) for v in values]))

    header = print_row('Name', 'Value', 'Def', 'Documentation', longest_optname, longest_value)
    print('-' * (len(header)))
    for v in sorted(values):
        if isinstance(v, pwndbglib.color.theme.ColoredParameter):
            value = generateColorFunction(v.value)(v.value)
            default = generateColorFunction(v.default)(v.default)
        elif isinstance(v.value, str):
            value = "'%s'" % str(v.value)
            default = str(v.default)
        else:
            value = repr(v.value)
            default = repr(v.default)
        print_row(v.optname, value, default, v.docstring, longest_optname, longest_value)

    print(hint('You can set theme variable with `set <theme-var> <value>`'))
    print(hint('You can generate theme config file using `themefile` '
               '- then put it in your .gdbinit after initializing pwndbg'))
