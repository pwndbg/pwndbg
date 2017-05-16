#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import pdb
import sys
import traceback

import gdb

import pwndbg.config
import pwndbg.stdio

try:
	import ipdb as pdb
except ImportError:
	pass

verbose = pwndbg.config.Parameter('exception-verbose', False, 'whether to print a full stacktracefor exceptions raised in Pwndbg commands')
debug = pwndbg.config.Parameter('exception-debugger', False, 'whether to debug exceptions raised in Pwndbg commands')

def handle():
    """Displays an exception to the user, optionally displaying a full traceback
    and spawning an interactive post-moretem debugger.

    Notes:
        - ``set exception-verbose on`` enables stack traces.
        - ``set exception-debugger on`` enables the post-mortem debugger.
    """
    # Display the error
    if debug or verbose:
        print(traceback.format_exc())
    else:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print(exc_type, exc_value)

    # Break into the interactive debugger
    if debug:
        with pwndbg.stdio.stdio:
            pdb.post_mortem()



@functools.wraps(pdb.set_trace)
def set_trace():
    """Enable sane debugging in Pwndbg by switching to the "real" stdio.
    """
    debugger = pdb.Pdb(stdin=sys.__stdin__,
                       stdout=sys.__stdout__,
                       skip=['pwndbg.stdio', 'pwndbg.exception'])
    debugger.set_trace()

pdb.set_trace = set_trace

@pwndbg.config.Trigger([verbose, debug])
def update():
    if verbose or debug:
        command = 'set python print-stack full'
    else:
        command = 'set python print-stack message'

    gdb.execute(command, from_tty=True, to_string=True)
