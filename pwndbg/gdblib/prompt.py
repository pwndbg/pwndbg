import re

import gdb

import pwndbg.decorators
import pwndbg.gdblib.events
import pwndbg.gdblib.functions
import pwndbg.lib.memoize
from pwndbg.color import disable_colors
from pwndbg.color import message
from pwndbg.lib.tips import get_tip_of_the_day

funcs_list_str = ", ".join(message.notice("$" + f.name) for f in pwndbg.gdblib.functions.functions)

num_pwndbg_cmds = sum(1 for _ in filter(lambda c: not c.shell, pwndbg.commands.commands))
num_shell_cmds = sum(1 for _ in filter(lambda c: c.shell, pwndbg.commands.commands))
hint_lines = (
    "loaded %i pwndbg commands and %i shell commands. Type %s for a list."
    % (num_pwndbg_cmds, num_shell_cmds, message.notice("pwndbg [--shell | --all] [filter]")),
    "created %s gdb functions (can be used with print/break)" % funcs_list_str,
)

for line in hint_lines:
    print(message.prompt("pwndbg: ") + message.system(line))

# noinspection PyPackageRequirements
show_tip = pwndbg.gdblib.config.add_param(
    "show-tips", True, "whether to display the tip of the day on startup"
)

cur = None


def initial_hook(*a):
    if show_tip and not pwndbg.decorators.first_prompt:
        colored_tip = re.sub(
            "`(.*?)`", lambda s: message.warn(s.group()[1:-1]), get_tip_of_the_day()
        )
        print(
            message.prompt("------- tip of the day")
            + message.system(" (disable with %s)" % message.notice("set show-tips off"))
            + message.prompt(" -------")
        )
        print((colored_tip))
    pwndbg.decorators.first_prompt = True

    prompt_hook(*a)
    gdb.prompt_hook = prompt_hook


context_shown = False


def prompt_hook(*a):
    global cur, context_shown

    new = (gdb.selected_inferior(), gdb.selected_thread())

    if cur != new:
        pwndbg.gdblib.events.after_reload(start=cur is None)
        cur = new

    if pwndbg.gdblib.proc.alive and pwndbg.gdblib.proc.thread_is_stopped and not context_shown:
        pwndbg.commands.context.context()
        context_shown = True


@pwndbg.gdblib.events.cont
def reset_context_shown(*a):
    global context_shown
    context_shown = False


@pwndbg.gdblib.config.trigger(message.config_prompt_color, disable_colors)
def set_prompt():
    prompt = "pwndbg> "

    if not disable_colors:
        prompt = "\x02" + prompt + "\x01"  # STX + prompt + SOH
        prompt = message.prompt(prompt)
        prompt = "\x01" + prompt + "\x02"  # SOH + prompt + STX

    gdb.execute("set prompt %s" % prompt)


if pwndbg.gdblib.events.before_prompt_event.is_real_event:
    gdb.prompt_hook = initial_hook

else:
    # Old GDBs doesn't have gdb.events.before_prompt, so we will emulate it using gdb.prompt_hook
    def extended_prompt_hook(*a):
        pwndbg.gdblib.events.before_prompt_event.invoke_callbacks()
        return prompt_hook(*a)

    gdb.prompt_hook = extended_prompt_hook
