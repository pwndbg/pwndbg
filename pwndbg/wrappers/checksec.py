#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


import pwndbg.commands
import pwndbg.wrappers


cmd_name = "checksec"

@pwndbg.memoize.reset_on_objfile
@pwndbg.wrappers.OnlyWithCommand(cmd_name)
@pwndbg.commands.OnlyWithFile
def get_raw_out():

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [get_raw_out.cmd_path, "--file", local_path]
    return pwndbg.wrappers.call_cmd(cmd)

@pwndbg.memoize.reset_on_objfile
@pwndbg.wrappers.OnlyWithCommand(cmd_name)
@pwndbg.commands.OnlyWithFile
def relro_status():
    relro = "No RELRO"

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [relro_status.cmd_path, "--file", local_path]
    out = pwndbg.wrappers.call_cmd(cmd)

    if "Full RELRO" in out:
        relro = "Full RELRO"
    elif "Partial RELRO" in out:
        relro = "Partial RELRO"

    return relro

@pwndbg.memoize.reset_on_objfile
@pwndbg.wrappers.OnlyWithCommand(cmd_name)
@pwndbg.commands.OnlyWithFile
def pie_status():
    pie = "No PIE"

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [pie_status.cmd_path, "--file", local_path]
    out = pwndbg.wrappers.call_cmd(cmd)

    if "PIE enabled" in out:
        pie = "PIE enabled"

    return pie
