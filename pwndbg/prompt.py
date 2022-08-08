import re

import gdb

import pwndbg.decorators
import pwndbg.events
import pwndbg.gdbutils
import pwndbg.memoize
from pwndbg.color import disable_colors
from pwndbg.color import message
from pwndbg.tips import get_tip_of_the_day

funcs_list_str = ', '.join(message.notice('$' + f.name) for f in pwndbg.gdbutils.functions.functions)

hint_lines = (
    'loaded %i commands. Type %s for a list.' % (len(pwndbg.commands.commands), message.notice('pwndbg [filter]')),
    'created %s gdb functions (can be used with print/break)' % funcs_list_str
)

for line in hint_lines:
    print(message.prompt('pwndbg: ') + message.system(line))

# noinspection PyPackageRequirements
show_tip = pwndbg.config.Parameter('show-tips', True, 'whether to display the tip of the day on startup')

cur = None


def initial_hook(*a):
    if show_tip and not pwndbg.decorators.first_prompt:
        colored_tip = re.sub('`(.*?)`', lambda s: message.warn(s.group()[1:-1]), get_tip_of_the_day())
        print(message.prompt('------- tip of the day') + message.system(' (disable with %s)' % message.notice('set show-tips off')) + message.prompt(' -------'))
        print((colored_tip))
    pwndbg.decorators.first_prompt = True

    prompt_hook(a)
    gdb.prompt_hook = prompt_hook


def prompt_hook(*a):
    global cur

    new = (gdb.selected_inferior(), gdb.selected_thread())

    if cur != new:
        pwndbg.events.after_reload(start=cur is None)
        cur = new

    if pwndbg.proc.alive and pwndbg.proc.thread_is_stopped:
        prompt_hook_on_stop(*a)


@pwndbg.memoize.reset_on_stop
def prompt_hook_on_stop(*a):
    pwndbg.commands.context.context()


@pwndbg.config.Trigger([message.config_prompt_color, disable_colors])
def set_prompt():
    prompt = "pwndbg> "

    if not disable_colors:
        prompt = "\x02" + prompt + "\x01"  # STX + prompt + SOH
        prompt = message.prompt(prompt)
        prompt = "\x01" + prompt + "\x02"  # SOH + prompt + STX

    gdb.execute('set prompt %s' % prompt)


if pwndbg.events.before_prompt_event.is_real_event:
    gdb.prompt_hook = initial_hook

else:
    # Old GDBs doesn't have gdb.events.before_prompt, so we will emulate it using gdb.prompt_hook
    def extended_prompt_hook(*a):
        pwndbg.events.before_prompt_event.invoke_callbacks()
        return prompt_hook(*a)

    gdb.prompt_hook = extended_prompt_hook
