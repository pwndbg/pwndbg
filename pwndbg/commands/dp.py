"""
Print a formatted message whenever a breakpoint is hit.
"""

from __future__ import annotations

import argparse
import re

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.stack
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.dbg_mod import BreakpointLocation
from pwndbg.dbg_mod import StopPoint

parser = argparse.ArgumentParser(
    description="Set a breakpoint that prints a formatted message on each hit.",
)
parser.add_argument("location", type=str, help="Function or address to break on.")
parser.add_argument("fmt", type=str, help="Printf-style format string.")
parser.add_argument("args", nargs="*", type=str, help="Optional printf arguments.")
parser.add_argument("--tid", action="store_true", help="Include the thread ID in output.")
parser.add_argument(
    "-d",
    "--d",
    type=str,
    default=None,
    metavar="DEPTH",
    help="Include caller function names up to DEPTH frames deep.",
)

# Matches a C printf conversion, including flags, width, precision and length
# modifiers. Python's `%` operator does not accept the length modifiers, so they
# are dropped when the format string is rewritten.
_SPECIFIER = re.compile(
    r"%(?P<flags>[-+ #0]*)(?P<width>\d*)(?:\.(?P<precision>\d+))?"
    r"(?P<length>hh|h|ll|l|j|z|t|L)?(?P<conversion>[diuoxXeEfFgGcsp])"
)

_PYTHON_CONVERSIONS = {"p": "#x", "u": "d"}


def _split_format(fmt: str) -> tuple[str, list[str]]:
    """Rewrite C printf conversions as Python `%` conversions.

    Returns the rewritten format string and the conversion character of every
    conversion that consumes an argument.
    """
    parts: list[str] = []
    conversions: list[str] = []
    i = 0
    while i < len(fmt):
        if fmt[i] != "%":
            parts.append(fmt[i])
            i += 1
            continue
        if fmt.startswith("%%", i):
            parts.append("%%")
            i += 2
            continue
        match = _SPECIFIER.match(fmt, i)
        if match is None:
            parts.append("%")
            i += 1
            continue
        conversion = match.group("conversion")
        spec = "%" + match.group("flags") + match.group("width")
        if match.group("precision") is not None:
            spec += "." + match.group("precision")
        spec += _PYTHON_CONVERSIONS.get(conversion, conversion)
        parts.append(spec)
        conversions.append(conversion)
        i = match.end()
    return "".join(parts), conversions


def _caller_chain(depth: int) -> list[str]:
    """Return up to `depth` caller function names, outermost first."""
    callers: list[str] = []
    for i, (_, symbol) in enumerate(pwndbg.aglib.stack.callstack_symbols_iter()):
        if i == 0 or symbol is None:
            continue
        # Symbols are resolved with an offset, e.g. `bar+27`, and versioned ELF
        # symbols may carry a suffix, e.g. `memcpy@@GLIBC_2.14`; keep the name.
        callers.append(symbol.split("+")[0].split("@@")[0])
        if len(callers) >= depth:
            break
    callers.reverse()
    return callers


def _default_arguments(conversions: list[str]) -> list[str]:
    """Return the ABI argument registers for the given conversions."""
    abi = pwndbg.aglib.arch.function_abi
    if abi is None:
        return []
    return [f"${register}" for register in abi.register_arguments[: len(conversions)]]


def _clean_arguments(raw_args: list[str]) -> list[str]:
    """Strip whitespace and trailing commas from user-provided arguments."""
    return [arg.rstrip(",") for arg in (raw.strip() for raw in raw_args) if arg]


def _evaluate(expression: str, conversion: str) -> int | str:
    """Evaluate `expression` in the current frame for the given conversion."""
    frame = pwndbg.dbg.selected_frame()
    if frame is None:
        raise pwndbg.dbg_mod.DebuggerError("No frame is selected")
    value = frame.evaluate_expression(expression)
    if conversion == "s":
        try:
            return value.string()
        except pwndbg.dbg_mod.DebuggerError:
            # A register or variable holding a pointer to the string.
            return bytes(pwndbg.aglib.memory.string(int(value))).decode(errors="replace")
    try:
        return int(value)
    except pwndbg.dbg_mod.DebuggerError:
        return value.value_to_human_readable()


def _parse_depth(depth: str | None) -> int | None:
    if depth is None:
        return None
    try:
        return max(int(depth, 0), 1)
    except ValueError:
        return 1


def _breakpoint_location(location: str) -> BreakpointLocation:
    try:
        return BreakpointLocation(address=int(location, 0))
    except ValueError:
        return BreakpointLocation(symbol=location)


@pwndbg.commands.Command(parser, command_name="dp", category=CommandCategory.BREAKPOINT)
def dp(location: str, fmt: str, args: list[str], tid: bool = False, d: str | None = None) -> None:
    try:
        python_fmt, conversions = _split_format(fmt)
        expressions = _clean_arguments(args) or _default_arguments(conversions)
        if len(expressions) < len(conversions):
            raise ValueError(
                f"{len(conversions)} conversion(s) in the format string but only "
                f"{len(expressions)} argument(s); pass them explicitly"
            )
        expressions = expressions[: len(conversions)]
        depth = _parse_depth(d)
        break_at = _breakpoint_location(location)

        def handler(_sp: StopPoint) -> bool:
            try:
                parts = []
                if tid:
                    thread = pwndbg.dbg.selected_thread()
                    if thread is not None:
                        parts.append(f"[TID: {thread.index()}]")
                if depth is not None:
                    callers = _caller_chain(depth)
                    if callers:
                        parts.append(" > ".join(callers) + " >")
                values = [_evaluate(expr, conv) for expr, conv in zip(expressions, conversions)]
                parts.append(python_fmt % tuple(values))
                print(" ".join(parts))
            except Exception as e:
                print(message.error(f"dp: {e}"))
            return False

        pwndbg.dbg.selected_inferior().break_at(break_at, stop_handler=handler)
        print(message.notice("[dp] breakpoint created"))
    except Exception as e:
        print(message.error(f"dp: {e}"))
