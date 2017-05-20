#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


import pwndbg.wrappers
import subprocess


@pwndbg.wrappers.OnlyWithCommand
def get_raw_out():

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [get_raw_out.command_path,"--file",local_path]
    return subprocess.check_output(cmd).decode('utf-8')


@pwndbg.wrappers.OnlyWithCommand
def relro_status():
    print("GETTING RELRO STATUS")
    relro = "No RELRO"

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [relro_status.command_path,"--file",local_path]
    out = subprocess.check_output(cmd).decode('utf-8')

    if "Full RELRO" in out:
        relro = "Full RELRO"
    elif "Partial RELRO" in out:
        relro = "Partial RELRO"
    print("GETTING RELRO STATUS END")

    return relro


@pwndbg.wrappers.OnlyWithCommand
def pie_status():
    print("GETTING PIE STATUS")

    pie = "No PIE"

    local_path = pwndbg.file.get_file(pwndbg.proc.exe)
    cmd = [pie_status.command_path,"--file",local_path]
    out = subprocess.check_output(cmd).decode('utf-8')

    if "PIE enabled" in out:
        pie = "PIE enabled"
    print("GETTING PIE STATUS END")

    return pie
