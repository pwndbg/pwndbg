"""
Talks to an XMLRPC server running inside of an active Binary Ninja instance,
in order to query it about the database. Allows symbol resolution and
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
from typing import TypeVar

import gdb
from typing_extensions import Concatenate
from typing_extensions import ParamSpec

import pwndbg
import pwndbg.decorators
import pwndbg.gdblib.arch
import pwndbg.gdblib.elf
import pwndbg.gdblib.events
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.integration
import pwndbg.lib.cache
from pwndbg.color import message

bn_rpc_host = pwndbg.config.add_param(
    "bn-rpc-host", "127.0.0.1", "binary ninja xmlrpc server address"
)
bn_rpc_port = pwndbg.config.add_param("bn-rpc-port", 31337, "binary ninja xmlrpc server port")
bn_timeout = pwndbg.config.add_param(
    "bn-timeout", 2, "time to wait for binary ninja xmlrpc in seconds"
)
pwndbg.config.add_param("bn-autosync", False, "whether to automatically run bn-sync every step")

_bn: xmlrpc.client.ServerProxy | None = None

# to avoid printing the same exception multiple times, we store the last exception here
_bn_last_exception = None

# to avoid checking the connection multiple times with no delay, we store the last time we checked it
_bn_last_connection_check = 0

P = ParamSpec("P")
T = TypeVar("T")


@pwndbg.decorators.only_after_first_prompt()
@pwndbg.config.trigger(bn_rpc_host, bn_rpc_port, pwndbg.integration.provider_name, bn_timeout)
def init_bn_rpc_client() -> None:
    global _bn, _bn_last_exception, _bn_last_connection_check

    if pwndbg.integration.provider_name.value != "binja":
        return

    now = time.time()
    if _bn is None and (now - _bn_last_connection_check) < int(bn_timeout) + 5:
        return

    addr = f"http://{bn_rpc_host}:{bn_rpc_port}"

    _bn = xmlrpc.client.ServerProxy(addr)
    socket.setdefaulttimeout(int(bn_timeout))

    exception = None  # (type, value, traceback)
    try:
        version = _bn.get_version()
        print(
            message.success(
                f"Pwndbg successfully connected to Binary Ninja ({version}) xmlrpc: {addr}"
            )
        )
    except TimeoutError:
        exception = sys.exc_info()
        _bn = None
    except OSError as e:
        if e.errno != errno.ECONNREFUSED:
            exception = sys.exc_info()
        _bn = None
    except xmlrpc.client.ProtocolError:
        exception = sys.exc_info()
        _bn = None

    if exception:
        if (
            not isinstance(_bn_last_exception, exception[0])
            or _bn_last_exception.args != exception[1].args
        ):
            if (
                hasattr(pwndbg.gdblib.config, "exception_verbose")
                and pwndbg.gdblib.config.exception_verbose
            ):
                print(message.error("[!] Binary Ninja xmlrpc error"))
                traceback.print_exception(*exception)
            else:
                exc_type, exc_value, _ = exception
                print(
                    message.error(
                        f"Failed to connect to Binary Ninja ({exc_type.__qualname__}: {exc_value})"
                    )
                )
                if exc_type is socket.timeout:
                    print(
                        message.notice("To increase the time to wait for Binary Ninja use `")
                        + message.hint("set bn-timeout <new-timeout-in-seconds>")
                        + message.notice("`")
                    )
                else:
                    print(
                        message.notice("For more info invoke `")
                        + message.hint("set exception-verbose on")
                        + message.notice("`")
                    )
                print(
                    message.notice("To disable Binary Ninja integration invoke `")
                    + message.hint("set bn-enabled off")
                    + message.notice("`")
                )

    _bn_last_exception = exception and exception[1]
    _bn_last_connection_check = now


def with_bn(func: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | None:
        if _bn is None:
            init_bn_rpc_client()
        if _bn is not None:
            return func(*args, **kwargs)
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
    return can_connect() is not None


@with_bn
def can_connect() -> bool:
    return True


def l2r(addr: int) -> int:
    exe = pwndbg.gdblib.elf.exe()
    if not exe:
        raise Exception("Can't find EXE base")
    result = (addr - pwndbg.gdblib.proc.binary_base_addr + base()) & pwndbg.gdblib.arch.ptrmask
    return result


def r2l(addr: int) -> int:
    exe = pwndbg.gdblib.elf.exe()
    if not exe:
        raise Exception("Can't find EXE base")
    result = (addr - base() + pwndbg.gdblib.proc.binary_base_addr) & pwndbg.gdblib.arch.ptrmask
    return result


@pwndbg.lib.cache.cache_until("objfile")
def base():
    return _bn.get_base()


@pwndbg.gdblib.events.stop
@with_bn
def auto_update_pc() -> None:
    pc = l2r(pwndbg.gdblib.regs.pc)
    if pwndbg.config.bn_autosync.value:
        navigate_to(pc)
    _bn.update_pc_tag(pc)


_managed_bps: Dict[int, gdb.Breakpoint] = {}


@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.stop
@pwndbg.gdblib.events.cont
@with_bn
def auto_update_bp() -> None:
    binja_bps = {r2l(addr) for addr in _bn.get_bp_tags()}
    for k in _managed_bps.keys() - binja_bps:
        _managed_bps.pop(k).delete()
    for k in binja_bps - _managed_bps.keys():
        bp = gdb.Breakpoint("*" + hex(k))
        _managed_bps[k] = bp


@pwndbg.gdblib.events.cont
@pwndbg.gdblib.events.exit
@with_bn
def auto_clear_pc() -> None:
    _bn.clear_pc_tag()


@with_bn
def navigate_to(addr: int) -> None:
    _bn.navigate_to(l2r(addr))

class BinjaProvider(pwndbg.integration.IntegrationProvider):
    @pwndbg.decorators.suppress_errors()
    @with_bn
    def get_symbol(self, addr: int) -> str | None:
        sym = _bn.get_symbol(l2r(addr))
        if sym is not None:
            return sym
        func = _bn.get_func_info(l2r(addr))
        if func is not None:
            return f"{func[0]}{addr - r2l(func[1]):+}"
        return None
