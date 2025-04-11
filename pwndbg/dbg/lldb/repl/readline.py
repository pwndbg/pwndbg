"""
Readline interface for the Pwndbg LLDB REPL.

Mostly concerns itself with argument completion.
"""

from __future__ import annotations

import contextlib
import functools
import os.path
import sys
from typing import Callable
from typing import ParamSpec
from typing import TypeVar

if sys.platform != "win32":
    import gnureadline as readline
else:
    import readline

    # pyreadline3 doesn't implement `set_completion_display_matches_hook`
    if not hasattr(readline, "set_completion_display_matches_hook"):
        readline.set_completion_display_matches_hook = lambda *args: None

import lldb

from pwndbg.color import message
from pwndbg.dbg.lldb import LLDB

P = ParamSpec("P")
T = TypeVar("T")


PROMPT = message.readline_escape(message.prompt, "pwndbg-lldb> ")
HISTORY_FILE = os.path.expanduser("~/.pwndbg_history")

complete_values = lldb.SBStringList()
complete_descrs = lldb.SBStringList()


def complete(dbg: LLDB, text: str, state: int) -> str | None:
    """
    Runs the tab autocompletion function for readline based on the values
    returned by `SBCommandInterpreter.HandleCompletion`.
    """
    global complete_values
    global complete_descrs
    if state == 0:
        complete_values.Clear()
        complete_descrs.Clear()
        dbg.debugger.GetCommandInterpreter().HandleCompletionWithDescriptions(
            text, len(text), len(text), 256, complete_values, complete_descrs
        )

    index = state + 1
    if index < complete_values.GetSize():
        s = complete_values.GetStringAtIndex(index)
        t = text.split()

        if text.rstrip() != text:
            t.append("")

        t[-1] = s
        return " ".join(t)

    return None


def display_completions(substitutions, matches, longest_match_len):
    """
    Display the completions found by `complete` in the style of LLDB.
    """
    global complete_descrs
    print()
    print("Available completions:")
    for i, match in enumerate(matches):
        padding = " " * (len(match) - longest_match_len + 1)
        description = complete_descrs.GetStringAtIndex(i + 1)

        print(f"\t{match}{padding} -- {description}")

    print(PROMPT, end="", flush=True)
    print(readline.get_line_buffer(), end="", flush=True)


def wrap_with_history(function: Callable[P, T]) -> Callable[P, T]:
    @functools.wraps(function)
    def _wrapped(*a: P.args, **kw: P.kwargs) -> T:
        with ctx_with_history():
            return function(*a, **kw)

    return _wrapped


@contextlib.contextmanager
def ctx_with_history():
    readline.set_history_length(1000)
    if os.path.exists(HISTORY_FILE):
        readline.read_history_file(HISTORY_FILE)

    try:
        yield
    finally:
        readline.write_history_file(HISTORY_FILE)


def enable_readline(dbg: LLDB):
    """
    Enables the readline functionality.
    """
    readline.set_completer(lambda text, state: complete(dbg, text, state))
    readline.set_completer_delims("")
    readline.set_completion_display_matches_hook(None)
    readline.set_completion_display_matches_hook(display_completions)
    readline.parse_and_bind("tab: complete")


def disable_readline():
    """
    Disables the readline functionality.
    """
    readline.set_completer(None)
    readline.set_completion_display_matches_hook(None)
