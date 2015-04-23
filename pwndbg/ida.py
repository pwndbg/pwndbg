#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Talks to an XMLRPC server running inside of an active IDA Pro instance,
in order to query it about the database.  Allows symbol resolution and
interactive debugging.
"""
import functools
import os
import socket
from contextlib import closing

import gdb
import pwndbg.arch
import pwndbg.compat
import pwndbg.elf
import pwndbg.events
import pwndbg.memoize
import pwndbg.memory
import pwndbg.regs

try:
    import xmlrpc.client as xmlrpclib
except:
    import xmlrpclib


xmlrpclib.Marshaller.dispatch[int] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)

if pwndbg.compat.python2:
    xmlrpclib.Marshaller.dispatch[long] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)


_ida = None

xmlrpclib.Marshaller.dispatch[type(0)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)


def setPort(port):
    global _ida
    _ida = xmlrpclib.ServerProxy('http://localhost:%s' % port)
    try:     _ida.here()
    except:  _ida = None

setPort(8888)

class withIDA(object):
    def __init__(self, fn):
        self.fn = fn
        functools.update_wrapper(self, fn)
    def __call__(self, *args, **kwargs):
        if _ida is not None:
            return self.fn(*args, **kwargs)
        return None

class takes_address(object):
    def __init__(self, fn):
        self.fn = fn
        functools.update_wrapper(self, fn)
    def __call__(self, address, *args):
        return self.fn(l2r(address), *args)

class returns_address(object):
    def __init__(self, fn):
        self.fn = fn
        functools.update_wrapper(self, fn)
    def __call__(self, *a, **kw):
        return r2l(self.fn(*a, **kw))

@withIDA
def available():
    return True

def l2r(addr):
    result = (addr - int(pwndbg.elf.exe().address) + base()) & pwndbg.arch.ptrmask
    return result

def r2l(addr):
    result = (addr - base() + int(pwndbg.elf.exe().address)) & pwndbg.arch.ptrmask
    return result

@pwndbg.memoize.reset_on_objfile
def base():
    result =  _ida.NextSeg(0) & ~(0xfff)
    if result < 0x100000:
        return 0

@withIDA
@takes_address
def Comment(addr):
    addr = l2r(addr)
    return _ida.GetCommentEx(addr, 0) or _ida.GetCommentEx(addr)

@withIDA
@takes_address
@pwndbg.memoize.reset_on_objfile
def Name(addr):
    return _ida.Name(addr)

@withIDA
@takes_address
@pwndbg.memoize.reset_on_objfile
def GetFuncOffset(addr):
    rv =  _ida.GetFuncOffset(addr)
    return rv

@withIDA
@returns_address
def here():
    return _ida.here()

@withIDA
@takes_address
def Jump(addr):
    return _ida.Jump(addr)

@withIDA
@takes_address
@pwndbg.memoize.reset_on_objfile
def Anterior(addr):
    hexrays_prefix = '\x01\x04; '
    lines = []
    for i in range(10):
        r = _ida.LineA(addr, i)
        if not r: break
        if r.startswith(hexrays_prefix):
            r = r[len(hexrays_prefix):]
        lines.append(r)
    return '\n'.join(lines)

@withIDA
def GetBreakpoints():
    for i in range(GetBptQty()):
        yield GetBptEA(i)

@withIDA
def GetBptQty():
    return _ida.GetBptQty()

@withIDA
@returns_address
def GetBptEA(i):
    return _ida.GetBptEA(i)

_breakpoints=[]

@pwndbg.events.cont
@pwndbg.events.stop
@withIDA
def UpdateBreakpoints():
    current = set(eval(b.location.lstrip('*')) for b in _breakpoints)
    want    = set(GetBreakpoints())

    # print(want)

    for addr in current-want:
        for bp in _breakpoints:
            if eval(bp.location) == addr:
                # print("delete", addr)
                bp.delete()
                break
        _breakpoints.remove(bp)

    for bp in want-current:
        if not pwndbg.memory.peek(bp):
            continue

        bp = gdb.Breakpoint('*' + hex(bp))
        _breakpoints.append(bp)
        # print(_breakpoints)


@withIDA
@takes_address
def SetColor(pc, color):
    return _ida.SetColor(pc, 1, color)


colored_pc = None

# @pwndbg.events.stop
# @withIDA
# def Auto_Color_PC():
#     global colored_pc
#     colored_pc = pwndbg.regs.pc
#     SetColor(colored_pc, 0x7f7fff)c

# @pwndbg.events.cont
# @withIDA
# def Auto_UnColor_PC():
#     global colored_pc
#     if colored_pc:
#         SetColor(colored_pc, 0xffffff)
#     colored_pc = None

@withIDA
@returns_address
@pwndbg.memoize.reset_on_objfile
def LocByName(name):
    return _ida.LocByName(str(name))

@withIDA
@takes_address
@returns_address
@pwndbg.memoize.reset_on_objfile
def PrevHead(addr):
    return _ida.PrevHead(addr)

@withIDA
@takes_address
@returns_address
@pwndbg.memoize.reset_on_objfile
def NextHead(addr):
    return _ida.NextHead(addr)

@withIDA
@takes_address
@pwndbg.memoize.reset_on_objfile
def GetFunctionName(addr):
    return _ida.GetFunctionName(addr)

@withIDA
@takes_address
@pwndbg.memoize.reset_on_objfile
def GetFlags(addr):
    return _ida.GetFlags(addr)

@withIDA
@pwndbg.memoize.reset_on_objfile
def isASCII(flags):
    return _ida.isASCII(flags)
