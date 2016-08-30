"""
Dumps all pwndbg-specific theme configuration points.
"""
from __future__ import unicode_literals

import pwndbg.config
import pwndbg.commands
import pwndbg.color.theme
from pwndbg.commands.config import print_row, extend_value_with_default
from pwndbg.color import generateColorFunction

@pwndbg.commands.Command
def theme():
    """Shows pwndbg-specific theme configuration points"""
    values = [v for k, v in pwndbg.config.__dict__.items()
              if isinstance(v, pwndbg.config.Parameter) and v.scope == 'theme']
    longest_optname = max(map(len, [v.optname for v in values]))
    longest_value = max(map(len, [extend_value_with_default(repr(v.value), repr(v.default)) for v in values]))

    header = print_row('Name', 'Value', 'Def', 'Documentation', longest_optname, longest_value)
    print('-' * (len(header)))
    for v in sorted(values):
        value = repr(v.value)
        default = repr(v.default)
        if isinstance(v, pwndbg.color.theme.ColoredParameter):
            value = generateColorFunction(v.value)(value)
            default = generateColorFunction(v.default)(default)
        print_row(v.optname, value, default, v.docstring, longest_optname, longest_value)
