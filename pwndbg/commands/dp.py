# pwndbg/commands/dp.py
# Week-1 MVP: `dp` — a safe, small wrapper to provide a "robust dprintf" style helper.
# Goals: accept format + args; optional --tid and -d/--depth; format safely and print.
# Future PRs can wire this to GDB's actual dprintf or set breakpoints.

from __future__ import annotations

import argparse
from typing import List

import gdb

import pwndbg
from pwndbg import log
from pwndbg.commands import Command
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    prog="dp", description="MVP wrapper for dprintf-like output (dp)."
)
parser.add_argument(
    "fmt", nargs="?", default="", help="Format string (e.g. 'malloc(%p)\\n')"
)
parser.add_argument("args", nargs="*", help="Optional arguments for the format string")
parser.add_argument(
    "--tid", action="store_true", help="Include current thread id in output"
)
parser.add_argument(
    "-d", "--depth", type=int, default=0, help="Caller depth (0=current)"
)


@Command(
    parser,
    category=CommandCategory.PWNDBG,
    command_name="dp",
    examples='dp "malloc(%p)\\n" $rdi --tid -d=1',
    notes="Week-1 MVP: formats a line, includes optional thread id and caller function.",
)
def dp(fmt: str, args: List[str], tid: bool = False, depth: int = 0) -> None:
    """
    Basic MVP for a dp command:
      - Format the string using Python (percent or str.format fallback)
      - Prepend a thread id marker if requested
      - Prepend a caller (function) if depth > 0 (best-effort)
      - Print via pwndbg.log.info (matches typical pwndbg output)
    This intentionally does not change program state or set breakpoints; it is a small,
    safe helper that follows the spirit of 'robust dprintf' for Week 1.
    """
    try:
        # Thread id best-effort
        tid_prefix = ""
        if tid:
            try:
                th = gdb.selected_thread()
                if th is not None:
                    # th.ptid is usually a tuple (pid, lwp, tid) on some platforms
                    ptid = getattr(th, "ptid", None)
                    if ptid and len(ptid) >= 3:
                        tid_prefix = f"[TID:{ptid[2]}] "
                    else:
                        # fallback to thread number
                        tid_prefix = f"[TID:{th.num}] "
            except Exception:
                # don't crash; just skip thread id
                tid_prefix = ""

        # Caller (best-effort)
        caller_prefix = ""
        if depth and depth > 0:
            try:
                frame = gdb.newest_frame()
                for _ in range(depth):
                    if frame is None:
                        break
                    frame = frame.older()
                if frame:
                    func = frame.name() or "<unknown>"
                    caller_prefix = f"{func} > "
            except Exception:
                caller_prefix = ""

        # Validate format string
        if fmt is None:
            log.error("dp: empty format string")
            return

        rendered = fmt
        if args:
            # Try percent-format first (common for gdb-style formats), then .format
            try:
                rendered = fmt % tuple(args)
            except Exception:
                try:
                    rendered = fmt.format(*args)
                except Exception as e:
                    log.error("dp: format/args error: %s", e)
                    return

        # Defensive: clamp extremely large outputs
        MAX_OUT = 200_000
        if isinstance(rendered, str) and len(rendered) > MAX_OUT:
            log.warning("dp: output too large; truncating")
            rendered = rendered[:MAX_OUT] + "...(truncated)"

        # Final assembled line
        line = f"{tid_prefix}{caller_prefix}{rendered}"
        # Use pwndbg's logging so output appears like other commands
        log.info(line)
    except Exception as e:
        log.exception("dp failed: %s", e)
