#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pdb
import sys
import traceback

import pwndbg.color as C
import pwndbg.config
import pwndbg.stdio

try:
	import ipdb as pdb
except ImportError:
	pass

verbose = pwndbg.config.Parameter('exception-verbose', False, 'whether to print a full stacktracefor exceptions raised in Pwndbg commands')
debug = pwndbg.config.Parameter('exception-debugger', False, 'whether to debug exceptions raised in Pwndbg commands')

def handle():
    # Display the error
    if debug or verbose:
        print(traceback.format_exc())
    else:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print(C.red(exc_type), exc_value)

    # Break into the interactive debugger
    if debug:
        with pwndbg.stdio.stdio:
            pdb.post_mortem()
