#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gdb

import pwndbglib.decorators
import pwndbglib.events
import pwndbglib.gdbutils
import pwndbglib.memoize
from pwndbglib.color import disable_colors
from pwndbglib.color import message

funcs_list_str = ', '.join(message.notice('$' + f.name) for f in pwndbglib.gdbutils.functions.functions)

hint_lines = (
    'loaded %i commands. Type %s for a list.' % (len(pwndbglib.commands.commands), message.notice('pwndbg [filter]')),
    'created %s gdb functions (can be used with print/break)' % funcs_list_str
)

for line in hint_lines:
    print(message.prompt('pwndbg: ') + message.system(line))

cur = None


def prompt_hook(*a):
    global cur
    pwndbglib.decorators.first_prompt = True

    new = (gdb.selected_inferior(), gdb.selected_thread())

    if cur != new:
        pwndbglib.events.after_reload(start=cur is None)
        cur = new

    if pwndbglib.proc.alive and pwndbglib.proc.thread_is_stopped:
        prompt_hook_on_stop(*a)


@pwndbglib.memoize.reset_on_stop
def prompt_hook_on_stop(*a):
    pwndbglib.commands.context.context()


@pwndbglib.config.Trigger([message.config_prompt_color, disable_colors])
def set_prompt():
    prompt = "pwndbg> "

    if not disable_colors:
        prompt = "\x02" + prompt + "\x01"  # STX + prompt + SOH
        prompt = message.prompt(prompt)
        prompt = "\x01" + prompt + "\x02"  # SOH + prompt + STX

    gdb.execute('set prompt %s' % prompt)


if pwndbglib.events.before_prompt_event.is_real_event:
    gdb.prompt_hook = prompt_hook

else:
    # Old GDBs doesn't have gdb.events.before_prompt, so we will emulate it using gdb.prompt_hook
    def extended_prompt_hook(*a):
        pwndbglib.events.before_prompt_event.invoke_callbacks()
        return prompt_hook(*a)

    gdb.prompt_hook = extended_prompt_hook
