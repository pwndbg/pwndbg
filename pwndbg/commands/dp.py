from __future__ import annotations

import argparse

import pwndbg.color.memory as mem_color
import pwndbg.commands
from pwndbg import dbg
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.dbg import BreakpointLocation

# ------------------------------------------------------------------------------
# Argument parser for the dp command
#
# dp <location> <fmt> [args...]
# Optional flags:
#   --tid   → include thread ID in printed output
#   --d N   → include N caller frames in the prefix
# ------------------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Debugger-evaluated dprintf-style breakpoint: dp <location> <fmt> [args ...]."
)

parser.add_argument("location", type=str)  # where to set the breakpoint
parser.add_argument("fmt", type=str)  # printf-style format string

parser.add_argument(
    "args",
    nargs="*",
    type=str,
)  # optional printf arguments

parser.add_argument(
    "--tid",
    action="store_true",
)  # include thread ID in output

parser.add_argument(
    "--d",
    type=str,
    default=None,
)  # depth of caller chain to print


# These frames are ignored when building the caller chain
# They belong to runtime startup rather than user code.
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


# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------


def _get_thread_id() -> int:
    """Return the index of the currently running thread."""
    return dbg.selected_thread().index()


def _extract_symbol_name(raw: str) -> str:
    """
    Extract a clean symbol name from a string like:
        '0x555555 <main+15>'
    or   '0x.... (foo@@GLIBC_2.0+13)'

    Removes offsets and version suffixes.
    """
    name = raw.split("(")[-1].split(")")[0].split("+")[0]
    return name.split("@@")[0]


def _get_caller_chain(levels: int = 1) -> list[str]:
    """
    Return a list of caller function names up to `levels` deep.

    Example output for --d=2 might be:
        ['main', 'helper']  → printed as "main > helper >"
    """
    if levels < 1:
        levels = 1

    frame = dbg.selected_frame()
    if frame is None:
        return []

    # Start from the caller of the current frame
    current = frame.parent()
    callers: list[str] = []

    # Walk up the stack until we hit runtime frames or reach the limit
    while current is not None and len(callers) < levels:
        raw = mem_color.get_address_and_symbol(current.pc())
        name = _extract_symbol_name(raw)
        if name in RUNTIME_STOP:
            break
        callers.append(name)
        current = current.parent()

    callers.reverse()  # print from outermost to inner
    return callers


def _escape_for_c_string(s: str) -> str:
    """
    Escape backslashes, quotes, and newlines so that the string can safely be
    fed into GDB/LLDB's printf-based execution.
    """
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _handle_dp_gdb(fmt: str, args: list[str], prefix: str):
    """
    Emit output inside GDB using its printf command.
    This is used when pwndbg is running under GDB.
    """
    import pwndbg.gdblib as gdblib

    fmt_full = f"{prefix} {fmt}" if prefix else fmt
    fmt_escaped = _escape_for_c_string(fmt_full)

    # Build a printf command like:
    #   printf "prefix message\n", arg1, arg2
    cmd = f'printf "{fmt_escaped}\\n"'
    if args:
        cmd += ", " + ", ".join(args)

    gdblib.gdb.execute(cmd)


def _handle_dp_lldb(fmt: str, args: list[str], prefix: str):
    """
    Emit output inside LLDB by constructing a C-expression that calls printf.
    This is used when pwndbg is running under LLDB.
    """
    inf = dbg.selected_inferior()

    fmt_full = f"{prefix} {fmt}" if prefix else fmt
    fmt_escaped = _escape_for_c_string(fmt_full)

    cmd = f'expression (void)printf("{fmt_escaped}\\n"'
    if args:
        cmd += ", " + ", ".join(args)
    cmd += ")"

    inf.runcmd(cmd)


def _clean_args(raw_args: list[str]) -> list[str]:
    """
    Clean the printf argument list:
    - strip whitespace
    - remove trailing commas
    """
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
    """
    Parse the --d argument:
    - None → no caller chain
    - invalid or <1 → treat as 1
    - allow C-style integers (0x10, etc.)
    """
    if d is None:
        return None
    try:
        depth = int(d, 0)
        if depth < 1:
            depth = 1
    except ValueError:
        depth = 1
    return depth


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
    registers = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
    return registers[: min(num_specs, len(registers))]


# ------------------------------------------------------------------------------
# The dp command implementation
# ------------------------------------------------------------------------------


@pwndbg.commands.Command(parser, command_name="dp", category=CommandCategory.MISC)
def dp(location: str, fmt: str, args: list[str], tid: bool = False, d: str | None = None):
    """
    The dp command:
    - resolves the symbol at <location>
    - sets a breakpoint there
    - prints a formatted message every time the breakpoint is hit
    - optionally includes thread ID (--tid)
    - optionally includes caller chain (--d N)
    """
    try:
        inf = dbg.selected_inferior()
        if inf is None:
            raise Exception("No inferior selected.")

        # Lookup the address associated with the symbol name
        val = inf.lookup_symbol(location)
        if val is None:
            raise Exception(f"Symbol {location!r} not found")

        fmt_template = fmt
        user_args = _clean_args(args)
        fmt_args = _infer_default_args(fmt_template, user_args)
        depth = _parse_depth(d)

        # This function will be called whenever the breakpoint hits
        def handler(sp):
            parts: list[str] = []

            # Add thread ID if requested
            if tid:
                thread_id = _get_thread_id()
                parts.append(f"[TID: {thread_id}]")

            # Add caller chain if requested
            if depth is not None:
                callers = _get_caller_chain(depth)
                if callers:
                    chain = " > ".join(callers) + " >"
                    parts.append(chain)

            prefix = " ".join(parts)

            if dbg.is_gdblib_available():
                _handle_dp_gdb(fmt_template, fmt_args, prefix)
            else:
                _handle_dp_lldb(fmt_template, fmt_args, prefix)

            return False

        # Create the actual breakpoint using pwndbg's infrastructure
        inf.break_at(BreakpointLocation(int(val)), stop_handler=handler)

        print(message.notice("[dp] breakpoint created"))

    except Exception as e:
        # Graceful user-facing error message
        print(message.error(f"dp: {e}"))
