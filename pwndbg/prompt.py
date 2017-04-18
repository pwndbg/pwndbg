#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import subprocess

import gdb

import pwndbg.events
import pwndbg.memoize
import pwndbg.stdio


def show_version():
    try:
        git_path = os.path.join(os.path.dirname(os.path.dirname(pwndbg.__file__)), '.git')
        commit_id = subprocess.check_output(['git', '--git-dir', git_path, 'rev-parse', 'HEAD'])
        commit_id = commit_id[:8].decode('utf-8')

        version_msg = 'Pwndbg version: %s' % commit_id
        print(pwndbg.color.light_yellow(version_msg))
    except:
        pass


def show_hint():
    hint_msg = 'Loaded %i commands. Type pwndbg [filter] for a list.' % len(pwndbg.commands._Command.commands)
    print(pwndbg.color.red(hint_msg))


show_version()
show_hint()
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
