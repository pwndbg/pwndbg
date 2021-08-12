#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import CalledProcessError

import pwndbglib.commands
import pwndbglib.memoize
import pwndbglib.wrappers

cmd_name = "checksec"
cmd_pwntools = ["pwn", "checksec"]

@pwndbglib.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
@pwndbglib.memoize.reset_on_objfile
def get_raw_out():
    local_path = pwndbglib.file.get_file(pwndbglib.proc.exe)
    try:
        return pwndbglib.wrappers.call_cmd(get_raw_out.cmd + ["--file=" + local_path])
    except CalledProcessError:
        pass
    try:
        return pwndbglib.wrappers.call_cmd(get_raw_out.cmd + ["--file", local_path])
    except CalledProcessError:
        pass
    return pwndbglib.wrappers.call_cmd(get_raw_out.cmd + [local_path])

@pwndbglib.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
def relro_status():
    relro = "No RELRO"
    out = get_raw_out()

    if "Full RELRO" in out:
        relro = "Full RELRO"
    elif "Partial RELRO" in out:
        relro = "Partial RELRO"

    return relro

@pwndbglib.wrappers.OnlyWithCommand(cmd_name, cmd_pwntools)
def pie_status():
    pie = "No PIE"
    out = get_raw_out()

    if "PIE enabled" in out:
        pie = "PIE enabled"

    return pie
