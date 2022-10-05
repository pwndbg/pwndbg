import gdb

import pwndbg.gdblib.events
import pwndbg.gdblib.typeinfo
from pwndbg.gdblib import arch_mod
from pwndbg.lib.memoize import reset_on_cont
from pwndbg.lib.memoize import reset_on_exit
from pwndbg.lib.memoize import reset_on_objfile
from pwndbg.lib.memoize import reset_on_prompt
from pwndbg.lib.memoize import reset_on_start
from pwndbg.lib.memoize import reset_on_stop
from pwndbg.lib.memoize import while_running

# TODO: Combine these `update_*` hook callbacks into one method


@pwndbg.gdblib.events.new_objfile
@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.stop
def update_typeinfo():
    pwndbg.gdblib.typeinfo.update()


@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.stop
@pwndbg.gdblib.events.new_objfile
def update_arch():
    arch_mod.update()


@pwndbg.gdblib.events.stop
@pwndbg.gdblib.events.reg_changed
@pwndbg.gdblib.events.mem_changed
def memoize_on_stop(*args):
    """
    Reset all caches from pwndbg.lib.memoize.reset_on_stop decorators

    Note that we have a `prompt_hook_on_stop` cached this way which
    is called in a prompt hook which displays context.
    """
    if not args:
        reset_on_stop._reset()
        return

    # This should never happen e.g. on stop event without further code changes to this function
    assert isinstance(args[0], (gdb.RegisterChangedEvent, gdb.MemoryChangedEvent))
    # On reg/mem changed events we skip clearing of cache of `prompt_hook_on_stop` function
    # if we don't do it, the prompt hook that calls it will display context after
    # a register or memory is set by the user which we do not want
    saved_caches = reset_on_stop.caches[:]
    prompt_hook_func = next(func for func in saved_caches if func.__name__ == "prompt_hook_on_stop")

    # Actually reset caches, except of the prompt_hook_func
    reset_on_stop.caches.remove(prompt_hook_func)
    reset_on_stop._reset()

    # Bring back all stop caches
    reset_on_stop.caches = saved_caches


@pwndbg.gdblib.events.before_prompt
def memoize_before_prompt():
    reset_on_prompt._reset()


@pwndbg.gdblib.events.cont
def memoize_on_cont():
    reset_on_cont._reset()


@pwndbg.gdblib.events.new_objfile
def memoize_on_new_objfile():
    reset_on_objfile._reset()


@pwndbg.gdblib.events.start
def memoize_on_start():
    while_running._start_caching()
    reset_on_start._reset()


@pwndbg.gdblib.events.exit
def memoize_on_exit():
    while_running._reset()
    reset_on_exit._reset()


def init():
    """Calls all GDB hook functions that need to be called when GDB/pwndbg
    itself is loaded, as opposed to when an actual hook event occurs
    """
    update_arch()
    update_typeinfo()


init()
