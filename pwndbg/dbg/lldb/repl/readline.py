"""
Readline interface for the Pwndbg LLDB REPL.

Mostly concerns itself with argument completion.
"""

from __future__ import annotations

import gnureadline as readline
import lldb

from pwndbg.color import message
from pwndbg.dbg.lldb import LLDB

PROMPT = message.prompt("pwndbg-lldb> ")

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
