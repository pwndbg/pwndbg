#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.events
import pwndbg.memoize
import pwndbg.stdio

msg = "Loaded %i commands.  Type pwndbg [filter] for a list." % len(pwndbg.commands._Command.commands)
print(pwndbg.color.red(msg))

cur = (gdb.selected_inferior(), gdb.selected_thread())

def prompt_hook(*a):
    global cur
    new = (gdb.selected_inferior(), gdb.selected_thread())

    if cur != new:
        pwndbg.events.after_reload(start=False)
        cur = new

    if pwndbg.proc.alive:
        prompt_hook_on_stop(*a)

@pwndbg.memoize.reset_on_stop
def prompt_hook_on_stop(*a):
    with pwndbg.stdio.stdio:
        pwndbg.commands.context.context()

gdb.prompt_hook = prompt_hook
