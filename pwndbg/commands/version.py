#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Displays gdb, python and pwndbg versions.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys
import os
from subprocess import check_output
from platform import platform
import argparse

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.ida
from pwndbg.color import message


def _gdb_version():
    try:
        return gdb.VERSION  # GDB >= 8.1 (or earlier?)
    except AttributeError:
        return gdb.execute('show version', to_string=True).split('\n')[0]


def _py_version():
    return sys.version.replace('\n', ' ')


def capstone_version():
    try:
        import capstone
        return '.'.join(map(str, capstone.cs_version()))
    except ImportError:
        return 'not found'


def unicorn_version():
    try:
        import unicorn
        return unicorn.__version__
    except ImportError:
        return 'not found'


def all_versions():
    gdb_str      = 'Gdb:      %s' % _gdb_version()
    py_str       = 'Python:   %s' % _py_version()
    pwndbg_str   = 'Pwndbg:   %s' % pwndbg.__version__

    capstone_str = 'Capstone: %s' % capstone_version()
    unicorn_str  = 'Unicorn:  %s' % unicorn_version()

    all_versions = (gdb_str, py_str, pwndbg_str, capstone_str, unicorn_str)

    ida_versions = pwndbg.ida.get_ida_versions()

    if ida_versions is not None:
        ida_version = 'IDA PRO:  %s' % ida_versions['ida']
        ida_py_ver  = 'IDA Py:   %s' % ida_versions['python']
        ida_hr_ver  = 'Hexrays:  %s' % ida_versions['hexrays']
        all_versions += (ida_version, ida_py_ver, ida_hr_ver)
    return all_versions
    

@pwndbg.commands.Command
def version():
    """
    Displays gdb, python and pwndbg versions.
    """
    print('\n'.join(map(message.system, all_versions())))


bugreport_parser = argparse.ArgumentParser(description='''
    Generate bugreport
    ''')
bugreport_parser.add_argument('--browse', '-b', action='store_true', help='Open browser on github/issues/new')

@pwndbg.commands.ArgparsedCommand(bugreport_parser)
def bugreport(browse=False):
    ISSUE_TEMPLATE = '''
<!--
Before reporting a new issue, make sure that we do not have any duplicates already open.
If there is one it might be good to take part in the discussion there.

Please make sure you have checked that the issue persists on LATEST pwndbg version.

Below is a template for BUG REPORTS.
Don't include it if this is a FEATURE REQUEST.
-->


### Description

<!--
Briefly describe the problem you are having in a few paragraphs.
-->

### Steps to reproduce

<!--
What do we have to do to reproduce the problem?
If this is connected to particular C/asm code, 
please provide the smallest C code that reproduces the issue.
-->

Gdb session history:
{gdb_history}

### My setup

<!--
Show us your gdb/python/pwndbg/OS/IDA Pro version (depending on your case).

NOTE: We are currently supporting only Ubuntu installations.
It is known that pwndbg is not fully working e.g. on Arch Linux (the heap stuff is not working there).
If you would like to change this situation - help us improving pwndbg and supporting other distros!

This can be displayed in pwndbg through `version` command.

If it is somehow unavailable, use:
* `show version` - for gdb
* `py import sys; print(sys.version)` - for python
* pwndbg version/git commit id
-->

{setup}'''

    gdb_config = gdb.execute('show configuration', to_string=True).split('\n')[:-3]
    all_info = all_versions()

    current_setup = 'Platform: %s\n' % platform()
    current_setup += '\n'.join(all_info)
    current_setup += '\n'.join(gdb_config)

    # get saved history size (not including current gdb session)
    gdb_history_file = gdb.execute('show history filename', to_string=True)
    gdb_history_file = gdb_history_file[len('The filename in which to record the command history is "'):-3]
    gdb_history_len = 0
    try:
        with open(gdb_history_file, 'r') as f:
            gdb_history_len = len(f.readlines())
    except FileNotFoundError:
        pass

    max_command_no = int(gdb.execute('show commands', to_string=True).split('\n')[-2].split('  ')[1]) - 1
    show_command_size = 10  # 'show command' returns 10 commands
    gdb_current_session_history = {}
    current_command_no = gdb_history_len + 1

    while current_command_no <= max_command_no:
        cmds = gdb.execute('show commands ' + str(current_command_no + (show_command_size//2)+1), to_string=True).split('\n')[:-1]
        for cmd in cmds:
            cmd_no = int(cmd.split('  ')[1])
            if cmd_no <= gdb_history_len:
                continue
            if current_command_no > max_command_no:
                break
            cmd = '  '.join(cmd.split('  ')[2:])
            gdb_current_session_history[cmd_no] = cmd
            current_command_no += 1

    gdb_current_session_history = [v for (k, v) in sorted(gdb_current_session_history.items())]
    gdb_current_session_history = '\n'.join(gdb_current_session_history)
    
    print(ISSUE_TEMPLATE.format(gdb_history=gdb_current_session_history, setup=current_setup))

    github_issue_url = 'https://github.com/pwndbg/pwndbg/issues/new'
    if browse:
        try:
            check_output(['xdg-open', github_issue_url])
        except:
            print('Please submit at ' + github_issue_url)    
    else:
        print('Please submit at ' + github_issue_url)