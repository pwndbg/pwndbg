"""
Dumps all pwndbg-specific theme configuration points.
"""
from __future__ import unicode_literals

import pwndbg.config
import pwndbg.commands
from pwndbg.commands.config import print_row

@pwndbg.commands.Command
def theme():
    """Shows pwndbg-specific theme configuration points"""
    header = print_row('Name','Value', 'Def', 'Documentation')
    print('-' * (len(header)))
    for k,v in sorted(pwndbg.config.__dict__.items()):
        if not isinstance(v, pwndbg.config.Parameter):
            continue
        if not v.scope == 'theme':
            continue
        print_row(v.optname, repr(v.value), repr(v.default), v.docstring)
