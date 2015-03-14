import gdb
import xmlrpc.client as xmlrpclib
import pwndbg.events
import pwndbg.memoize
import pwndbg.elf
import socket
from contextlib import closing

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
        self.__name__ = fn.__name__
    def __call__(self, *args, **kwargs):
        if _ida:
            return self.fn(*args, **kwargs)

class takes_address(object):
    def __init__(self, fn):
        self.fn = fn
        self.__name__ = fn.__name__
    def __call__(self, address):
        return self.fn(l2r(address))

class returns_address(object):
    def __init__(self, fn):
        self.fn = fn
        self.__name__ = fn.__name__
    def __call__(self, *a, **kw):
        return r2l(self.fn(*a, **kw))

def l2r(addr):
    return addr - int(pwndbg.elf.exe().address) + base()

def r2l(addr):
    return addr - base() + int(pwndbg.elf.exe().address)

@pwndbg.memoize.reset_on_objfile
def base():
    return _ida.NextSeg(0) & ~(0xfff)

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
    return request_nocache('map(GetBptEA, range(GetBptQty()))')

_breakpoints=[]

@pwndbg.events.cont
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
        bp = gdb.Breakpoint('*' + hex(bp))
        _breakpoints.append(bp)
        # print(_breakpoints)
