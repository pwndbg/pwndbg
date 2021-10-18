#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Get information about the GLibc
"""

import functools
import re

import gdb

import pwndbg.config
import pwndbg.heap
import pwndbg.memoize
import pwndbg.memory
import pwndbg.proc
import pwndbg.search
import pwndbg.symbol

safe_lnk = pwndbg.config.Parameter('safe-linking', 'auto', 'whether glibc use safe-linking (on/off/auto)')


@pwndbg.proc.OnlyWhenRunning
@pwndbg.memoize.reset_on_objfile
def get_version():
    if pwndbg.heap.current.libc_has_debug_syms():
        addr = pwndbg.symbol.address(b'__libc_version')
        if addr is not None:
            ver = pwndbg.memory.string(addr)
            return tuple([int(_) for _ in ver.split(b'.')])
    for addr in pwndbg.search.search(b'GNU C Library'):
        banner = pwndbg.memory.string(addr)
        ret = re.search(rb"release version (\d+)\.(\d+)", banner)
        if ret:
            return tuple(int(_) for _ in ret.groups())
    return None


def OnlyWhenGlibcLoaded(function):
    @functools.wraps(function)
    def _OnlyWhenGlibcLoaded(*a, **kw):
        if get_version() is not None:
            return function(*a, **kw)
        else:
            print('%s: GLibc not loaded yet.' % function.__name__)
    return _OnlyWhenGlibcLoaded


@OnlyWhenGlibcLoaded
def check_safe_linking():
    """
    Safe-linking is a glibc 2.32 mitigation; see:
    - https://lanph3re.blogspot.com/2020/08/blog-post.html
    - https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/
    """
    return (get_version() >= (2, 32) or safe_lnk == "on") and safe_lnk != "off"
