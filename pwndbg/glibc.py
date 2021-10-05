#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Get information about the GLibc
"""

import re

import gdb

import pwndbg.memoize
import pwndbg.memory
import pwndbg.symbol


@pwndbg.memoize.reset_on_start
def get_version():
    addr = pwndbg.symbol.address('banner')
    if addr is None:
        return (0, 0)
    banner = pwndbg.memory.string(addr)
    ret = re.search(rb"release version (\d+)\.(\d+)", banner)
    if ret:
        return tuple(int(_) for _ in ret.groups())
    return (0, 0)

@pwndbg.memoize.reset_on_start
def check_safe_linking():
    return get_version() >= (2, 32)
