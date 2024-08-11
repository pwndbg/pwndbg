from __future__ import annotations

from os import environ
from typing import Any
from typing import Tuple

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.decorators
import pwndbg.gdblib.events
import pwndbg.gdblib.functions
import pwndbg.gdblib.proc
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

    num_pwndbg_cmds = sum(
        1 for _ in filter(lambda c: not (c.shell or c.is_alias), pwndbg.commands.commands)
    )
    num_shell_cmds = sum(1 for _ in filter(lambda c: c.shell, pwndbg.commands.commands))
    hint_lines = (
        "loaded %i pwndbg commands and %i shell commands. Type %s for a list."
        % (num_pwndbg_cmds, num_shell_cmds, message.notice("pwndbg [--shell | --all] [filter]")),
        f"created {funcs_list_str} GDB functions (can be used with print/break)",
    )

    for line in hint_lines:
        print(message.prompt("pwndbg: ") + message.system(line))


def prompt_hook(*a: Any) -> None:
    global cur, context_shown, last_alive_state

    new = (gdb.selected_inferior(), gdb.selected_thread())

    if cur != new:
        pwndbg.gdblib.events.after_reload(start=cur is None)
        cur = new

    if pwndbg.gdblib.proc.alive and pwndbg.gdblib.proc.thread_is_stopped and not context_shown:
        pwndbg.commands.context.context()
        context_shown = True

    # set prompt again when alive state changes
    if last_alive_state != pwndbg.gdblib.proc.alive:
        last_alive_state = pwndbg.gdblib.proc.alive
        set_prompt()


@pwndbg.dbg.event_handler(EventType.CONTINUE)
def reset_context_shown(*a: Any) -> None:
    global context_shown
    context_shown = False


@pwndbg.config.trigger(message.config_prompt_color, disable_colors)
def set_prompt() -> None:
    prompt = "pwndbg> "

    if not disable_colors:
        prompt = "\x02" + prompt + "\x01"  # STX + prompt + SOH
        if pwndbg.gdblib.proc.alive:
            prompt = message.alive_prompt(prompt)
        else:
            prompt = message.prompt(prompt)
        prompt = "\x01" + prompt + "\x02"  # SOH + prompt + STX

    gdb.execute(f"set prompt {prompt}")


gdb.prompt_hook = initial_hook
