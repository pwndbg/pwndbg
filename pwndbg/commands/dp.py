"""
Robust dprintf-style breakpoint printing with optional thread ID and caller chain.
"""

from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.stack
import pwndbg.commands
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

RUNTIME_STOP = {
    "_start",
    "__libc_start_main",
    "__libc_start_call_main",
    "__clone",
    "__GI___clone",
    "__GI___clone_internal",
    "__GI___pthread_start",
    "__pthread_start",
    "__GI___futex_abstimed_wait_cancelable64",
}


def _get_thread_id() -> int:
    return pwndbg.dbg.selected_thread().index()


def _get_caller_chain(levels: int) -> list[str]:
    if levels < 1:
        levels = 1

    callers: list[str] = []
    for i, (_, symbol) in enumerate(pwndbg.aglib.stack.callstack_symbols_iter()):
        if i == 0:
            continue
        if symbol is None:
            continue
        name = symbol.split("+")[0].split("@@")[0]
        if name in RUNTIME_STOP:
            break
        callers.append(name)
        if len(callers) >= levels:
            break

    callers.reverse()
    return callers


def _escape_for_c_string(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _handle_dp_gdb(fmt: str, args: list[str], prefix: str) -> None:
    import gdb

    fmt_full = f"{prefix} {fmt}" if prefix else fmt
    fmt_escaped = _escape_for_c_string(fmt_full)
    cmd = f'printf "{fmt_escaped}\\n"'
    if args:
        cmd += ", " + ", ".join(args)
    gdb.execute(cmd, from_tty=False)


def _handle_dp_lldb(fmt: str, args: list[str], prefix: str) -> None:
    inf = pwndbg.dbg.selected_inferior()
    fmt_full = f"{prefix} {fmt}" if prefix else fmt
    fmt_escaped = _escape_for_c_string(fmt_full)
    cmd = f'expression (void)printf("{fmt_escaped}\\n"'
    if args:
        cmd += ", " + ", ".join(args)
    cmd += ")"
    inf.runcmd(cmd)


def _clean_args(raw_args: list[str]) -> list[str]:
    cleaned: list[str] = []
    for raw in raw_args:
        s = raw.strip()
        if not s:
            continue
        if s.endswith(","):
            s = s[:-1].rstrip()
        if s:
            cleaned.append(s)
    return cleaned


def _parse_depth(d: str | None) -> int | None:
    if d is None:
        return None
    try:
        depth = int(d, 0)
    except ValueError:
        depth = 1
    return max(depth, 1)


def _count_format_args(fmt: str) -> int:
    count = 0
    i = 0
    n = len(fmt)
    while i < n:
        if fmt[i] == "%":
            if i + 1 < n and fmt[i + 1] == "%":
                i += 2
                continue
            count += 1
            i += 1
            while i < n and not fmt[i].isalpha():
                i += 1
            if i < n:
                i += 1
        else:
            i += 1
    return count


def _infer_default_args(fmt: str, explicit_args: list[str]) -> list[str]:
    if explicit_args:
        return explicit_args
    num_specs = _count_format_args(fmt)
    if num_specs <= 0:
        return explicit_args
    abi = pwndbg.aglib.arch.function_abi
    if abi is None:
        return explicit_args
    registers = [f"${reg}" for reg in abi.register_arguments]
    return registers[: min(num_specs, len(registers))]


@pwndbg.commands.Command(parser, command_name="dp", category=CommandCategory.BREAKPOINT)
def dp(location: str, fmt: str, args: list[str], tid: bool = False, d: str | None = None) -> None:
    try:
        inf = pwndbg.dbg.selected_inferior()
        val = inf.lookup_symbol(location)
        if val is None:
            raise ValueError(f"Symbol {location!r} not found")

        fmt_template = fmt
        fmt_args = _infer_default_args(fmt_template, _clean_args(args))
        depth = _parse_depth(d)

        def handler(_sp: StopPoint) -> bool:
            parts: list[str] = []
            if tid:
                parts.append(f"[TID: {_get_thread_id()}]")
            if depth is not None:
                callers = _get_caller_chain(depth)
                if callers:
                    parts.append(" > ".join(callers) + " >")
            prefix = " ".join(parts)

            if pwndbg.dbg.is_gdblib_available():
                _handle_dp_gdb(fmt_template, fmt_args, prefix)
            else:
                _handle_dp_lldb(fmt_template, fmt_args, prefix)
            return False

        inf.break_at(BreakpointLocation(int(val)), stop_handler=handler)
        print(message.notice("[dp] breakpoint created"))
    except Exception as e:
        print(message.error(f"dp: {e}"))
