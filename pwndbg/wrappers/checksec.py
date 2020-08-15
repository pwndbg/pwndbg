#!/usr/bin/env python
# -*- coding: utf-8 -*-

from re import search
from subprocess import STDOUT
from subprocess import CalledProcessError

import pwndbg.commands
import pwndbg.memoize
import pwndbg.wrappers

cmd_name = "checksec"
cmd_pwntools = ["pwn", "checksec"]

@pwndbg.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
@pwndbg.memoize.reset_on_objfile
def get_raw_out():
    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    try:
        return pwndbg.wrappers.call_cmd(get_raw_out.cmd + ["--file=" + local_path])
    except CalledProcessError:
        pass
    try:
        return pwndbg.wrappers.call_cmd(get_raw_out.cmd + ["--file", local_path])
    except CalledProcessError:
        pass
    return pwndbg.wrappers.call_cmd(get_raw_out.cmd + [local_path])

@pwndbg.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
def relro_status():
    relro = "No RELRO"
    out = get_raw_out()

    if "Full RELRO" in out:
        relro = "Full RELRO"
    elif "Partial RELRO" in out:
        relro = "Partial RELRO"

    return relro

@pwndbg.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
def pie_status():
    pie = "No PIE"
    out = get_raw_out()

    if "PIE enabled" in out:
        pie = "PIE enabled"

    return pie
