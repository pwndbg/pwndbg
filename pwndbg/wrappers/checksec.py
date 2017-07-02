#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


import pwndbg.commands
import pwndbg.wrappers


cmd_name = "checksec"

@pwndbg.wrappers.OnlyWithCommand(cmd_name)
def get_raw_out():

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [get_raw_out.cmd_path, "--file", local_path]
    return pwndbg.wrappers.call_cmd(cmd)

@pwndbg.wrappers.OnlyWithCommand(cmd_name)
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

@pwndbg.wrappers.OnlyWithCommand(cmd_name)
def pie_status():
    pie = "No PIE"

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [pie_status.cmd_path, "--file", local_path]
    out = pwndbg.wrappers.call_cmd(cmd)

    if "PIE enabled" in out:
        pie = "PIE enabled"

    return pie
