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
from typing import Tuple
from typing import TypeVar

import pygments
import pygments.formatters
import pygments.style
import pygments.token
from typing_extensions import ParamSpec

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.elf
import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.aglib.symbol
import pwndbg.color
import pwndbg.color.context as context_color
import pwndbg.decorators
import pwndbg.integration
import pwndbg.lib.cache
import pwndbg.lib.config
from pwndbg.aglib.nearpc import c as nearpc_color
from pwndbg.aglib.nearpc import ljust_padding
from pwndbg.color import message
from pwndbg.color import theme
from pwndbg.dbg import BreakpointLocation
from pwndbg.dbg import EventType
from pwndbg.dbg import StopPoint
from pwndbg.lib.functions import Argument
from pwndbg.lib.functions import Function

bn_rpc_host = pwndbg.config.add_param(
    "bn-rpc-host", "127.0.0.1", "Binary Ninja XML-RPC server host"
)
bn_rpc_port = pwndbg.config.add_param("bn-rpc-port", 31337, "Binary Ninja XML-RPC server port")
bn_timeout = pwndbg.config.add_param(
    "bn-timeout", 2, "time to wait for Binary Ninja XML-RPC, in seconds"
)
bn_autosync = pwndbg.config.add_param(
    "bn-autosync", False, "whether to automatically run bn-sync every step"
)
bn_il_level = pwndbg.config.add_param(
    "bn-il-level",
    "hlil",
    "the IL level to use when displaying Binary Ninja decompilation",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["disasm", "llil", "mlil", "hlil"],
)

_bn: xmlrpc.client.ServerProxy | None = None

# to avoid printing the same exception multiple times, we store the last exception here
_bn_last_exception = None

# to avoid checking the connection multiple times with no delay, we store the last time we checked it
_bn_last_connection_check = 0

P = ParamSpec("P")
T = TypeVar("T")
K = TypeVar("K")


@pwndbg.decorators.only_after_first_prompt()
@pwndbg.config.trigger(bn_rpc_host, bn_rpc_port, pwndbg.integration.provider_name, bn_timeout)
def init_bn_rpc_client() -> None:
    global _bn, _bn_last_exception, _bn_last_connection_check

    if pwndbg.integration.provider_name.value != "binja":
        return

    xmlrpc.client.MAXINT = 10**100  # type: ignore[misc]
    xmlrpc.client.MININT = -(10**100)  # type: ignore[misc]

    now = time.time()
    if _bn is None and (now - _bn_last_connection_check) < int(bn_timeout) + 5:
        return

    addr = f"http://{bn_rpc_host}:{bn_rpc_port}"

    _bn = xmlrpc.client.ServerProxy(addr)
    socket.setdefaulttimeout(int(bn_timeout))

    exception = None  # (type, value, traceback)
    try:
        version: str = _bn.get_version()
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
            if pwndbg.config.exception_verbose:
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


def with_bn(fallback: K = None) -> Callable[[Callable[P, T]], Callable[P, T | K]]:
    global _bn

    def decorator(func: Callable[P, T]) -> Callable[P, T | K]:
        global _bn

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | K:
            global _bn
            if _bn is None:
                init_bn_rpc_client()

            try:
                if _bn is not None:
                    return func(*args, **kwargs)
            except ConnectionRefusedError:
                print(message.error("[!] Binary Ninja connection refused"))
                _bn = None

            return fallback

        return wrapper

    return decorator


@pwndbg.lib.cache.cache_until("stop")
def available() -> bool:
    return can_connect() is not None


@with_bn()
def can_connect() -> bool:
    return True


def l2r(addr: int) -> int:
    result = (addr - pwndbg.aglib.proc.binary_base_addr + base()) & pwndbg.aglib.arch.ptrmask
    return result


def r2l(addr: int) -> int:
    result = (addr - base() + pwndbg.aglib.proc.binary_base_addr) & pwndbg.aglib.arch.ptrmask
    return result


@pwndbg.lib.cache.cache_until("stop")
def base():
    return _bn.get_base()


@pwndbg.dbg.event_handler(EventType.STOP)
@with_bn()
def auto_update_pc() -> None:
    if not pwndbg.aglib.proc.alive:
        return
    pc = pwndbg.aglib.regs.pc
    if bn_autosync.value:
        navigate_to(pc)
    _bn.update_pc_tag(l2r(pc))


_managed_bps: Dict[int, StopPoint] = {}


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.STOP)
@pwndbg.dbg.event_handler(EventType.CONTINUE)
@with_bn()
def auto_update_bp() -> None:
    if not pwndbg.aglib.proc.alive:
        return
    bps: List[int] = _bn.get_bp_tags()
    binja_bps = {r2l(addr) for addr in bps}
    for k in _managed_bps.keys() - binja_bps:
        bp = _managed_bps.pop(k)
        bp.remove()

    inf = pwndbg.dbg.selected_inferior()
    for k in binja_bps - _managed_bps.keys():
        bp = inf.break_at(BreakpointLocation(k))
        _managed_bps[k] = bp


@pwndbg.dbg.event_handler(EventType.CONTINUE)
@pwndbg.dbg.event_handler(EventType.EXIT)
@with_bn()
def auto_clear_pc() -> None:
    _bn.clear_pc_tag()


@with_bn()
def navigate_to(addr: int) -> None:
    _bn.navigate_to(l2r(addr))


def bn_to_pygment_tok(tok: str) -> Any:
    return pygments.token.string_to_tokentype(f"BinaryNinja.{tok.title()}")


def bn_to_pygment_theme(theme: Dict[str, str]) -> Dict[Any, str]:
    ret = {bn_to_pygment_tok(k): v for (k, v) in theme.items()}
    ret[pygments.token.Token] = theme["TextToken"]
    return ret


class DarkTheme(pygments.style.Style):
    styles = bn_to_pygment_theme(
        {
            "TextToken": "#e0e0e0",
            "InstructionToken": "#eddfb3",
            "OperandSeparatorToken": "#e0e0e0",
            "RegisterToken": "#e0e0e0",
            "IntegerToken": "#a2d9af",
            "PossibleAddressToken": "#a2d9af",
            "BeginMemoryOperandToken": "#e0e0e0",
            "EndMemoryOperandToken": "#e0e0e0",
            "FloatingPointToken": "#a2d9af",
            "AnnotationToken": "#dac4d1",
            "CodeRelativeAddressToken": "#a2d9af",
            "ArgumentNameToken": "#e0e0e0",
            "HexDumpByteValueToken": "#e0e0e0",
            "HexDumpSkippedByteToken": "#e0e0e0",
            "HexDumpInvalidByteToken": "#909090",
            "HexDumpTextToken": "#e0e0e0",
            "OpcodeToken": "#909090",
            "StringToken": "#dac4d1",
            "CharacterConstantToken": "#dac4d1",
            "KeywordToken": "#eddfb3",
            "TypeNameToken": "#edbd81",
            "FieldNameToken": "#b0dde4",
            "NameSpaceToken": "#80c6e9",
            "NameSpaceSeparatorToken": "#80c6e9",
            "TagToken": "#e0e0e0",
            "StructOffsetToken": "#b0dde4",
            "StructOffsetByteValueToken": "#e0e0e0",
            "StructureHexDumpTextToken": "#e0e0e0",
            "GotoLabelToken": "#80c6e9",
            "CommentToken": "#dac4d1",
            "PossibleValueToken": "#e0e0e0",
            "PossibleValueTypeToken": "#e0e0e0",
            "ArrayIndexToken": "#a2d9af",
            "IndentationToken": "#5d5d5d",
            "UnknownMemoryToken": "#909090",
            "EnumerationMemberToken": "#eddfb3",
            "OperationToken": "#89a4b1",
            "BaseStructureNameToken": "#dac4d1",
            "BaseStructureSeparatorToken": "#dac4d1",
            "BraceToken": "#e0e0e0",
            "CodeSymbolToken": "#80c6e9",
            "DataSymbolToken": "#8ee6ed",
            "LocalVariableToken": "#e0e0e0",
            "ImportToken": "#edbd81",
            "AddressDisplayToken": "#a2d9af",
            "IndirectImportToken": "#edbd81",
            "ExternalSymbolToken": "#edbd81",
            "StackVariableToken": "#c1dcc7",
            "AddressSeparatorToken": "#e0e0e0",
        }
    )


class LightTheme(pygments.style.Style):
    styles = bn_to_pygment_theme(
        {
            "TextToken": "#1f1f1f",
            "InstructionToken": "#8d8d2d",
            "OperandSeparatorToken": "#1f1f1f",
            "RegisterToken": "#1f1f1f",
            "IntegerToken": "#30820d",
            "PossibleAddressToken": "#30820d",
            "BeginMemoryOperandToken": "#1f1f1f",
            "EndMemoryOperandToken": "#1f1f1f",
            "FloatingPointToken": "#30820d",
            "AnnotationToken": "#bf2624",
            "CodeRelativeAddressToken": "#30820d",
            "ArgumentNameToken": "#1f1f1f",
            "HexDumpByteValueToken": "#1f1f1f",
            "HexDumpSkippedByteToken": "#1f1f1f",
            "HexDumpInvalidByteToken": "#7a7a7a",
            "HexDumpTextToken": "#1f1f1f",
            "OpcodeToken": "#7a7a7a",
            "StringToken": "#203635",
            "CharacterConstantToken": "#203635",
            "KeywordToken": "#8d8d2d",
            "TypeNameToken": "#e07c35",
            "FieldNameToken": "#35dae0",
            "NameSpaceToken": "#00a4c7",
            "NameSpaceSeparatorToken": "#00a4c7",
            "TagToken": "#1f1f1f",
            "StructOffsetToken": "#35dae0",
            "StructOffsetByteValueToken": "#1f1f1f",
            "StructureHexDumpTextToken": "#1f1f1f",
            "GotoLabelToken": "#00a4c7",
            "CommentToken": "#bf2624",
            "PossibleValueToken": "#1f1f1f",
            "PossibleValueTypeToken": "#1f1f1f",
            "ArrayIndexToken": "#30820d",
            "IndentationToken": "#bcbcbc",
            "UnknownMemoryToken": "#7a7a7a",
            "EnumerationMemberToken": "#8d8d2d",
            "OperationToken": "#5b848d",
            "BaseStructureNameToken": "#bf2624",
            "BaseStructureSeparatorToken": "#bf2624",
            "BraceToken": "#1f1f1f",
            "CodeSymbolToken": "#00a4c7",
            "DataSymbolToken": "#278cad",
            "LocalVariableToken": "#1f1f1f",
            "ImportToken": "#e07c35",
            "AddressDisplayToken": "#30820d",
            "IndirectImportToken": "#e07c35",
            "ExternalSymbolToken": "#e07c35",
            "StackVariableToken": "#275016",
            "AddressSeparatorToken": "#1f1f1f",
        }
    )


themes = {}
themes["dark"] = DarkTheme
themes["light"] = LightTheme

style = theme.add_param(
    "bn-decomp-style",
    "dark",
    "decompilation highlight theme for Binary Ninja",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=list(themes.keys()),
)


class BinjaProvider(pwndbg.integration.IntegrationProvider):
    @pwndbg.decorators.suppress_errors()
    @with_bn()
    @pwndbg.lib.cache.cache_until("stop")
    def get_symbol(self, addr: int) -> str | None:
        sym: str | None = _bn.get_symbol(l2r(addr))
        if sym is not None:
            return sym
        func: Tuple[str, int] | None = _bn.get_func_info(l2r(addr))
        if func is not None:
            diff = addr - r2l(func[1])
            if diff:
                return f"{func[0]}{diff:+}"
            else:
                return func[0]
        dv: Tuple[str, int] | None = _bn.get_data_info(l2r(addr))
        if dv is not None:
            diff = addr - r2l(dv[1])
            if diff:
                return f"{dv[0]}{addr - r2l(dv[1]):+}"
            else:
                return dv[0]
        return None

    @pwndbg.decorators.suppress_errors(fallback=())
    @with_bn(fallback=())
    def get_versions(self) -> Tuple[str, ...]:
        bn_version: str = _bn.get_version()
        py_version: str = _bn.get_py_version()
        return (
            f"Binary Ninja:        {bn_version}",
            f"Binary Ninja Python: {py_version}",
        )

    @pwndbg.decorators.suppress_errors(fallback=True)
    @with_bn(fallback=True)
    @pwndbg.lib.cache.cache_until("stop")
    def is_in_function(self, addr: int) -> bool:
        return _bn.get_func_info(l2r(addr)) is not None

    @pwndbg.decorators.suppress_errors(fallback=[])
    @with_bn(fallback=[])
    def get_comment_lines(self, addr: int) -> List[str]:
        comments: List[str] = _bn.get_comments(l2r(addr))
        return comments

    @pwndbg.decorators.suppress_errors()
    @with_bn()
    def decompile(self, addr: int, lines: int) -> List[str] | None:
        decomp: List[Tuple[int, List[Tuple[str, str]]]] | None = _bn.decompile_func(
            l2r(addr), bn_il_level.value
        )
        if not decomp:
            return None
        decomp = [
            (r2l(addr), toks) for (addr, toks) in decomp if not all(t[0].isspace() for t in toks)
        ]
        ind = min(
            ((i, x) for (i, x) in enumerate(decomp) if x[0] >= addr),
            key=lambda t: t[1][0],
            default=(len(decomp) - 1, None),
        )[0]
        start = ind - (lines - 1) // 2
        end = ind + lines // 2 + 1

        # shift range to be in bounds
        if start < 0:
            diff = -start
            start += diff
            end += diff
        elif end > len(decomp):
            diff = len(decomp) - end
            start -= diff
            end -= diff
        start = max(start, 0)
        end = min(end, len(decomp))
        sliced = decomp[start:end]

        addrs = []
        syms = []
        min_indents = None
        for addr, decomp_toks in sliced:
            addrs.append(hex(addr))
            syms.append(f"<{pwndbg.aglib.symbol.resolve_addr(addr)}>")
            indents = 0
            for _, ty in decomp_toks:
                if ty == "IndentationToken":
                    indents += 1
                else:
                    break
            if min_indents is None:
                min_indents = indents
            else:
                min_indents = min(min_indents, indents)

        ret = []
        formatter = pygments.formatters.Terminal256Formatter(style=themes[str(style)])
        target_addr = decomp[ind][0]
        for (addr, decomp_toks), addr_str, sym in zip(
            sliced, ljust_padding(addrs), ljust_padding(syms)
        ):
            addr_str = nearpc_color.address(addr_str)
            sym = nearpc_color.symbol(sym)
            whole_addr = f"{addr_str} {sym}"
            if addr == target_addr:
                whole_addr = context_color.highlight(whole_addr)
                prefix = str(pwndbg.config.nearpc_prefix)
            else:
                prefix = " " * len(pwndbg.config.nearpc_prefix)
            prefix = nearpc_color.prefix(prefix)
            line = f" {prefix} {whole_addr} "
            # add comments above the line
            ret += [
                " " * len(pwndbg.color.unstylize(line))
                + pygments.format([(bn_to_pygment_tok("CommentToken"), x)], formatter)
                for x in self.get_comment_lines(addr)
            ]
            toks = []
            for text, ty in decomp_toks[min_indents:]:
                toks.append((bn_to_pygment_tok(ty), text))
            line += pygments.format(toks, formatter)
            ret.append(line)
        return ret

    @pwndbg.decorators.suppress_errors()
    @with_bn()
    def get_func_type(self, addr: int) -> Function | None:
        ty: Tuple[Tuple[str, int, str], List[Tuple[str, int, str]]] = _bn.get_func_type(l2r(addr))
        if ty is None:
            return None
        args = [Argument(type=x[0], derefcnt=x[1], name=x[2]) for x in ty[1]]
        return Function(type=ty[0][0], derefcnt=ty[0][1], name=ty[0][2], args=args)

    @pwndbg.decorators.suppress_errors()
    @with_bn()
    @pwndbg.lib.cache.cache_until("stop")
    def get_stack_var_name(self, addr: int) -> str | None:
        cur = pwndbg.dbg.selected_frame()
        # there is no earlier frame so we give up
        if addr < pwndbg.aglib.regs.read_reg("sp", frame=cur):
            return None
        newest = True
        # try to find the oldest frame that's earlier than the address
        while True:
            upper = cur.parent()
            if upper is None:
                break

            upper_sp = pwndbg.aglib.regs.read_reg("sp", frame=upper)
            if upper_sp > addr:
                break

            cur = upper
            newest = False

        regs = [
            (name, val)
            for name in pwndbg.aglib.regs.common
            if (val := pwndbg.aglib.regs.read_reg(name, frame=cur)) is not None
        ]
        # put stack pointer and frame pointer at the front
        regs.sort(
            key=lambda x: {pwndbg.aglib.regs.stack: 0, pwndbg.aglib.regs.frame: 1}.get(x[0], 2)
        )
        ret: Tuple[int, str, int] | None = _bn.get_stack_var_name(l2r(int(cur.pc())), regs, addr)
        if ret is None:
            return None
        (conf, func, var) = ret
        suffix = "" if conf > 200 else "?"
        if newest:
            return f"{var}{suffix}"
        else:
            return f"{func}:{var}{suffix}"
