"""
Talks to an XMLRPC server running inside of an active IDA Pro instance,
in order to query it about the database.  Allows symbol resolution and
interactive debugging.
"""

from __future__ import annotations

import errno
import functools
import socket
import sys
import time
import traceback
import xmlrpc.client
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple
from typing import TypeVar

import gdb
from typing_extensions import Concatenate
from typing_extensions import ParamSpec

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.elf
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import pwndbg.decorators
import pwndbg.integration
import pwndbg.lib.cache
import pwndbg.lib.funcparser
from pwndbg.color import message
from pwndbg.dbg import EventType
from pwndbg.lib.functions import Function

ida_rpc_host = pwndbg.config.add_param("ida-rpc-host", "127.0.0.1", "ida xmlrpc server address")
ida_rpc_port = pwndbg.config.add_param("ida-rpc-port", 31337, "ida xmlrpc server port")
ida_timeout = pwndbg.config.add_param("ida-timeout", 2, "time to wait for ida xmlrpc in seconds")


_ida: xmlrpc.client.ServerProxy | None = None

# to avoid printing the same exception multiple times, we store the last exception here
_ida_last_exception: BaseException | None = None

# to avoid checking the connection multiple times with no delay, we store the last time we checked it
_ida_last_connection_check = 0

P = ParamSpec("P")
T = TypeVar("T")


@pwndbg.decorators.only_after_first_prompt()
@pwndbg.config.trigger(ida_rpc_host, ida_rpc_port, pwndbg.integration.provider_name, ida_timeout)
def init_ida_rpc_client() -> None:
    global _ida, _ida_last_exception, _ida_last_connection_check

    if pwndbg.integration.provider_name.value != "ida":
        return

    xmlrpc.client.MAXINT = 10**100  # type: ignore[misc]
    xmlrpc.client.MININT = -(10**100)  # type: ignore[misc]

    now = time.time()
    if _ida is None and (now - _ida_last_connection_check) < int(ida_timeout) + 5:
        return

    addr = f"http://{ida_rpc_host}:{ida_rpc_port}"

    _ida = xmlrpc.client.ServerProxy(addr)
    socket.setdefaulttimeout(int(ida_timeout))

    exception = None  # (type, value, traceback)
    try:
        _ida.here()
        print(message.success(f"Pwndbg successfully connected to Ida Pro xmlrpc: {addr}"))
        idc._update()
    except TimeoutError:
        exception = sys.exc_info()
        _ida = None
    except OSError as e:
        if e.errno != errno.ECONNREFUSED:
            exception = sys.exc_info()
        _ida = None
    except xmlrpc.client.ProtocolError:
        exception = sys.exc_info()
        _ida = None

    if exception:
        if (
            not isinstance(_ida_last_exception, exception[0])
            or _ida_last_exception.args != exception[1].args
        ):
            if hasattr(pwndbg.config, "exception_verbose") and pwndbg.config.exception_verbose:
                print(message.error("[!] Ida Pro xmlrpc error"))
                traceback.print_exception(*exception)
            else:
                exc_type, exc_value, _ = exception
                print(
                    message.error(
                        f"Failed to connect to IDA Pro ({exc_type.__qualname__}: {exc_value})"
                    )
                )
                if exc_type is socket.timeout:
                    print(
                        message.notice("To increase the time to wait for IDA Pro use `")
                        + message.hint("set ida-timeout <new-timeout-in-seconds>")
                        + message.notice("`")
                    )
                else:
                    print(
                        message.notice("For more info invoke `")
                        + message.hint("set exception-verbose on")
                        + message.notice("`")
                    )
                print(
                    message.notice("To disable IDA Pro integration invoke `")
                    + message.hint("set integration-provider none")
                    + message.notice("`")
                )

    _ida_last_exception = exception and exception[1]
    _ida_last_connection_check = now


def withIDA(func: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | None:
        if _ida is None:
            init_ida_rpc_client()
        if _ida is not None:
            return func(*args, **kwargs)
        return None

    return wrapper


def withHexrays(func: Callable[P, T]) -> Callable[P, T | None]:
    @withIDA
    @functools.wraps(func)
    def wrapper(*a: P.args, **kw: P.kwargs) -> T | None:
        if _ida is not None and _ida.init_hexrays_plugin():
            return func(*a, **kw)
        return None

    return wrapper


def takes_address(function: Callable[Concatenate[int, P], T]) -> Callable[Concatenate[int, P], T]:
    @functools.wraps(function)
    def wrapper(address: int, *args: P.args, **kwargs: P.kwargs) -> T:
        return function(l2r(address), *args, **kwargs)

    return wrapper


def returns_address(function: Callable[P, int]) -> Callable[P, int]:
    @functools.wraps(function)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> int:
        return r2l(function(*args, **kwargs))

    return wrapper


@pwndbg.lib.cache.cache_until("stop")
def available() -> bool:
    if pwndbg.integration.provider_name.value != "ida":
        return False
    return can_connect()


@withIDA
def can_connect() -> bool:
    return True


def l2r(addr: int) -> int:
    exe = pwndbg.aglib.elf.exe()
    if not exe:
        raise Exception("Can't find EXE base")
    result = (addr - int(exe.address) + base()) & pwndbg.aglib.arch.ptrmask
    return result


def r2l(addr: int) -> int:
    exe = pwndbg.aglib.elf.exe()
    if not exe:
        raise Exception("Can't find EXE base")
    result = (addr - base() + int(exe.address)) & pwndbg.aglib.arch.ptrmask
    return result


def remote(function) -> None:
    """Runs the provided function in IDA's interpreter.

    The function must be self-contained and not reference any
    global variables."""


@pwndbg.lib.cache.cache_until("objfile")
def base():
    segaddr: int = _ida.get_next_seg(0)
    base: int = _ida.get_fileregion_offset(segaddr)

    return segaddr - base


@withIDA
@takes_address
def Comment(addr: int):
    return _ida.get_cmt(addr, 0) or _ida.get_cmt(addr)


@withIDA
@takes_address
@pwndbg.lib.cache.cache_until("objfile")
def Name(addr: int):
    return _ida.get_name(addr, 0x1)  # GN_VISIBLE


@withIDA
@takes_address
@pwndbg.lib.cache.cache_until("objfile")
def GetFuncOffset(addr: int):
    rv = _ida.get_func_off_str(addr)
    return rv


@withIDA
@takes_address
def GetFuncAttr(addr: int, attr: int):
    rv = _ida.get_func_attr(addr, attr)
    return rv


@withIDA
@takes_address
@pwndbg.lib.cache.cache_until("objfile")
def GetType(addr: int):
    rv = _ida.get_type(addr)
    return rv


@withIDA
@returns_address
def here() -> int:
    return _ida.here()  # type: ignore[return-value]


@withIDA
@takes_address
def Jump(addr: int):
    # uses C++ api instead of idc one to avoid activating the IDA window
    return _ida.jumpto(addr, -1, 0)


@withIDA
@takes_address
@pwndbg.lib.cache.cache_until("objfile")
def Anterior(addr: int):
    hexrays_prefix = b"\x01\x04; "
    lines = []
    for i in range(10):
        r: bytes | None = _ida.get_extra_cmt(addr, 0x3E8 + i)  # E_PREV
        if not r:
            break
        if r.startswith(hexrays_prefix):
            r = r[len(hexrays_prefix) :]
        lines.append(r)
    return b"\n".join(lines)


@withIDA
def GetBreakpoints():
    for i in range(GetBptQty()):
        yield GetBptEA(i)


@withIDA
def GetBptQty():
    return _ida.get_bpt_qty()


@withIDA
@returns_address
def GetBptEA(i: int) -> int:
    return _ida.get_bpt_ea(i)  # type: ignore[return-value]


_breakpoints: List[gdb.Breakpoint] = []


@pwndbg.dbg.event_handler(EventType.CONTINUE)
@pwndbg.dbg.event_handler(EventType.STOP)
@withIDA
def UpdateBreakpoints() -> None:
    # XXX: Remove breakpoints from IDA when the user removes them.
    current = {eval(b.location.lstrip("*")) for b in _breakpoints}
    want = set(GetBreakpoints())

    for addr in current - want:
        for bp in _breakpoints:
            if int(bp.location.lstrip("*"), 0) == addr:
                bp.delete()
                break
        _breakpoints.remove(bp)

    for addr in want - current:
        if not pwndbg.aglib.memory.peek(addr):
            continue

        bp = gdb.Breakpoint("*" + hex(int(addr)))
        _breakpoints.append(bp)


@withIDA
@takes_address
def SetColor(pc, color):
    return _ida.set_color(pc, 1, color)


colored_pc = None


@pwndbg.dbg.event_handler(EventType.STOP)
@withIDA
def Auto_Color_PC() -> None:
    global colored_pc
    colored_pc = pwndbg.aglib.regs.pc
    SetColor(colored_pc, 0x7F7FFF)


@pwndbg.dbg.event_handler(EventType.CONTINUE)
@withIDA
def Auto_UnColor_PC() -> None:
    global colored_pc
    if colored_pc:
        SetColor(colored_pc, 0xFFFFFF)
    colored_pc = None


@withIDA
@returns_address
@pwndbg.lib.cache.cache_until("objfile")
def LocByName(name) -> int:
    return _ida.get_name_ea_simple(str(name))  # type: ignore[return-value]


@withIDA
@takes_address
@returns_address
@pwndbg.lib.cache.cache_until("objfile")
def PrevHead(addr):
    return _ida.prev_head(addr)


@withIDA
@takes_address
@returns_address
@pwndbg.lib.cache.cache_until("objfile")
def NextHead(addr):
    return _ida.next_head(addr)


@withIDA
@takes_address
@pwndbg.lib.cache.cache_until("objfile")
def GetFunctionName(addr):
    return _ida.get_func_name(addr)


@withIDA
@takes_address
@pwndbg.lib.cache.cache_until("objfile")
def GetFlags(addr):
    return _ida.get_full_flags(addr)


@withIDA
@pwndbg.lib.cache.cache_until("objfile")
def isASCII(flags):
    return _ida.is_strlit(flags)


@withIDA
@takes_address
@pwndbg.lib.cache.cache_until("objfile")
def ArgCount(address) -> None:
    pass


@withIDA
def SaveBase(path: str):
    return _ida.save_database(path)


@withIDA
def GetIdbPath():
    return _ida.get_idb_path()


@takes_address
@pwndbg.lib.cache.cache_until("stop")
def has_cached_cfunc(addr):
    return _ida.has_cached_cfunc(addr)


@withHexrays
@takes_address
@pwndbg.lib.cache.cache_until("stop")
def decompile(addr):
    return _ida.decompile(addr)


@withHexrays
@takes_address
@pwndbg.lib.cache.cache_until("stop")
def decompile_context(pc, context_lines):
    return _ida.decompile_context(pc, context_lines)


@withIDA
@pwndbg.lib.cache.cache_until("forever")
def get_ida_versions() -> Dict[str, str]:
    return _ida.versions()  # type: ignore[return-value]


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetStrucQty():
    return _ida.get_struc_qty()


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetStrucId(idx):
    return _ida.get_struc_by_idx(idx)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetStrucName(sid):
    return _ida.get_struc_name(sid)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetStrucSize(sid):
    return _ida.get_struc_size(sid)


@withIDA
@takes_address
@pwndbg.lib.cache.cache_until("stop")
def GetFrameId(addr):
    return _ida.get_frame_id(addr)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetMemberQty(sid):
    return _ida.get_member_qty(sid)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetMemberSize(sid, offset):
    return _ida.get_member_size(sid, offset)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetMemberId(sid, offset):
    return _ida.get_member_id(sid, offset)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetMemberName(sid, offset):
    return _ida.get_member_name(sid, offset)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetMemberOffset(sid, member_name):
    return _ida.get_member_offset(sid, member_name)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetMemberFlag(sid, offset):
    return _ida.get_member_flag(sid, offset)


@withIDA
@pwndbg.lib.cache.cache_until("stop")
def GetStrucNextOff(sid, offset):
    return _ida.get_next_offset(sid, offset)


class IDC:
    query = "{k:v for k,v in globals()['idc'].__dict__.items() if isinstance(v, int)}"

    def __init__(self) -> None:
        if available():
            self._update()

    def _update(self) -> None:
        data: Dict[Any, Any] = _ida.eval(self.query)
        self.__dict__.update(data)


idc = IDC()


def print_member(sid, offset) -> None:
    mname = GetMemberName(sid, offset) or "(no name)"
    msize = GetMemberSize(sid, offset) or 0
    print(f"    +{offset:#x} - {mname} [{msize:#x} bytes]")


def print_structs() -> None:
    for i in range(GetStrucQty() or 0):
        sid = GetStrucId(i)

        name = GetStrucName(sid)
        size = GetStrucSize(sid)

        print(f"{name} - {size:#x} bytes")

        offset = 0
        while offset < size:
            print_member(sid, offset)
            offset = GetStrucNextOff(sid, offset)


ida_replacements = {
    "__int64": "signed long long int",
    "__int32": "signed int",
    "__int16": "signed short",
    "__int8": "signed char",
    "__uint64": "unsigned long long int",
    "__uint32": "unsigned int",
    "__uint16": "unsigned short",
    "__uint8": "unsigned char",
    "_BOOL_1": "unsigned char",
    "_BOOL_2": "unsigned short",
    "_BOOL_4": "unsigned int",
    "_BYTE": "unsigned char",
    "_WORD": "unsigned short",
    "_DWORD": "unsigned int",
    "_QWORD": "unsigned long long",
    "__pure": "",
    "__hidden": "",
    "__return_ptr": "",
    "__struct_ptr": "",
    "__array_ptr": "",
    "__fastcall": "",
    "__cdecl": "",
    "__thiscall": "",
    "__userpurge": "",
}


class IdaProvider(pwndbg.integration.IntegrationProvider):
    @pwndbg.decorators.suppress_errors()
    @withIDA
    def get_symbol(self, addr: int) -> str | None:
        exe = pwndbg.aglib.elf.exe()
        if exe:
            exe_map = pwndbg.aglib.vmmap.find(exe.address)
            if exe_map and addr in exe_map:
                return Name(addr) or GetFuncOffset(addr) or None
        return None

    @pwndbg.decorators.suppress_errors(fallback=())
    def get_versions(self) -> Tuple[str, ...]:
        ida_versions = get_ida_versions()

        if ida_versions is not None:
            ida_version = f"IDA PRO:  {ida_versions['ida']}"
            ida_py_ver = f"IDA Py:   {ida_versions['python']}"
            ida_hr_ver = f"Hexrays:  {ida_versions['hexrays']}"
            return (ida_version, ida_py_ver, ida_hr_ver)
        return ()

    @pwndbg.decorators.suppress_errors(fallback=True)
    @withIDA
    def is_in_function(self, addr: int) -> bool:
        return available() and bool(GetFunctionName(addr))

    @pwndbg.decorators.suppress_errors(fallback=[])
    @withIDA
    def get_comment_lines(self, addr: int) -> List[str]:
        pre = Anterior(addr)
        return pre.decode().split("\n") if pre else []

    @pwndbg.decorators.suppress_errors()
    @withIDA
    def decompile(self, addr: int, lines: int) -> List[str] | None:
        code = decompile_context(addr, lines // 2)
        if code:
            return code.splitlines()
        else:
            return None

    @pwndbg.decorators.suppress_errors()
    @withIDA
    def get_func_type(self, addr: int) -> Function | None:
        typename: str = GetType(addr)

        if typename:
            typename += ";"

            # GetType() does not include the name.
            typename = typename.replace("(", " function_name(", 1)

            for k, v in ida_replacements.items():
                typename = typename.replace(k, v)

            return pwndbg.lib.funcparser.ExtractFuncDeclFromSource(typename + ";")

        return None
