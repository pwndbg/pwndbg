from __future__ import annotations

from os import environ
from typing import Any
from typing import Tuple

import gdb

import pwndbg
import pwndbg.aglib.proc
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.decorators
import pwndbg.gdblib.events
import pwndbg.gdblib.functions
import pwndbg.lib.cache
import pwndbg.profiling
from pwndbg.color import disable_colors
from pwndbg.color import message
from pwndbg.dbg import EventType
from pwndbg.lib.tips import color_tip
from pwndbg.lib.tips import get_tip_of_the_day

# noinspection PyPackageRequirements
show_tip = pwndbg.config.add_param(
    "show-tips", True, "whether to display the tip of the day on startup"
)

cur: Tuple[gdb.Inferior, gdb.InferiorThread] | None = None


def initial_hook(*a: Any) -> None:
    if show_tip and not pwndbg.decorators.first_prompt:
        colored_tip = color_tip(get_tip_of_the_day())
        print(
            message.prompt("------- tip of the day")
            + message.system(" (disable with %s)" % message.notice("set show-tips off"))
            + message.prompt(" -------")
        )
        print(colored_tip)
    pwndbg.decorators.first_prompt = True

    prompt_hook(*a)

    if environ.get("PWNDBG_PROFILE") == "1":
        pwndbg.profiling.profiler.stop("pwndbg-first-prompt.pstats")

    gdb.prompt_hook = prompt_hook


context_shown = False
last_alive_state = False


def show_hint() -> None:
    funcs_list_str = ", ".join(
        message.notice("$" + f.name) for f in pwndbg.gdblib.functions.functions
    )

    hint_lines = (
        "loaded %i pwndbg commands. Type %s for a list."
        % (len(pwndbg.commands.commands), message.notice("pwndbg [filter]")),
        f"created {funcs_list_str} GDB functions (can be used with print/break)",
    )

    for line in hint_lines:
        print(message.prompt("pwndbg: ") + message.system(line))


def thread_is_stopped() -> bool:
    """
    This detects whether selected thread is stopped.
    It is not stopped in situations when gdb is executing commands
    that are attached to a breakpoint by `command` command.

    For more info see issue #229 ( https://github.com/pwndbg/pwndbg/issues/299 )
    :return: Whether gdb executes commands attached to bp with `command` command.
    """
    t = gdb.selected_thread()
    if not t:
        return False
    return t.is_stopped()


def prompt_hook(*a: Any) -> None:
    global cur, context_shown, last_alive_state

    new = (gdb.selected_inferior(), gdb.selected_thread())

    if cur != new:
        pwndbg.gdblib.events.after_reload(fire_start=cur is None)
        cur = new

    if not context_shown and pwndbg.aglib.proc.alive and thread_is_stopped():
        pwndbg.commands.context.selected_history_index = None
        pwndbg.commands.context.context()
        context_shown = True

    # set prompt again when alive state changes
    if last_alive_state != pwndbg.aglib.proc.alive:
        last_alive_state = pwndbg.aglib.proc.alive
        set_prompt()


@pwndbg.dbg.event_handler(EventType.CONTINUE)
def reset_context_shown(*a: Any) -> None:
    global context_shown
    context_shown = False


@pwndbg.config.trigger(message.config_prompt_color, disable_colors)
def set_prompt() -> None:
    prompt = "pwndbg> "

    if not disable_colors:
        if pwndbg.aglib.proc.alive:
            prompt = message.readline_escape(message.alive_prompt, prompt)
        else:
            prompt = message.readline_escape(message.prompt, prompt)

    gdb.execute(f"set prompt {prompt}")


gdb.prompt_hook = initial_hook
