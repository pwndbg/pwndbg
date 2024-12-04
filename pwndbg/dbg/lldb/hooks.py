"""
Code that sets up hooks for LLDB events.
"""

from __future__ import annotations

import pwndbg
import pwndbg.aglib.strings
import pwndbg.aglib.typeinfo
from pwndbg.dbg import EventType
from pwndbg.dbg.lldb import LLDB


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.STOP)
def update_typeinfo() -> None:
    pwndbg.aglib.typeinfo.update()
    pwndbg.aglib.arch_mod.update()


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def reset_config() -> None:
    pwndbg.aglib.kernel._kconfig = None


@pwndbg.dbg.event_handler(EventType.START)
def on_start() -> None:
    pwndbg.aglib.memory.update_min_addr()


@pwndbg.dbg.event_handler(EventType.STOP)
def on_stop() -> None:
    pwndbg.aglib.strings.update_length()


@pwndbg.dbg.event_handler(EventType.EXIT)
def on_exit() -> None:
    pwndbg.aglib.file.reset_remote_files()


import pwndbg.lib.cache

pwndbg.lib.cache.connect_clear_caching_events(
    {
        "exit": (pwndbg.dbg.event_handler(EventType.EXIT),),
        "objfile": (pwndbg.dbg.event_handler(EventType.NEW_MODULE),),
        "start": (pwndbg.dbg.event_handler(EventType.START),),
        "stop": (
            pwndbg.dbg.event_handler(EventType.STOP),
            pwndbg.dbg.event_handler(EventType.MEMORY_CHANGED),
            pwndbg.dbg.event_handler(EventType.REGISTER_CHANGED),
        ),
        "cont": (
            pwndbg.dbg.event_handler(EventType.CONTINUE),
            pwndbg.dbg.event_handler(EventType.MEMORY_CHANGED),
            pwndbg.dbg.event_handler(EventType.REGISTER_CHANGED),
        ),
        "prompt": (),
        "forever": (),
    },
)

# As we don't have support for MEMORY_CHANGED, REGISTER_CHANGED, or NEW_THREAD
# yet, we disable these cache types, as we can't provide the same behavior for
# them as GDB can.
#
# TODO: Implement missing event types and re-enable the cache types that depend on them.
#
# FIXME: `stop` and `cont` have been enabled for performance reasons, but aren't 100% correct.
pwndbg.lib.cache.IS_CACHING_DISABLED_FOR["stop"] = False
pwndbg.lib.cache.IS_CACHING_DISABLED_FOR["thread"] = True
pwndbg.lib.cache.IS_CACHING_DISABLED_FOR["cont"] = False

should_show_context = False


@pwndbg.dbg.event_handler(EventType.STOP)
def renew_show_context():
    global should_show_context
    should_show_context = True


def prompt_hook():
    # Clear the prompt cache manually.
    pwndbg.lib.cache.clear_cache("prompt")

    global should_show_context
    if should_show_context:
        pwndbg.commands.context.context()
        should_show_context = False


# Install the prompt hook.
assert isinstance(pwndbg.dbg, LLDB)
dbg: LLDB = pwndbg.dbg

dbg.prompt_hook = prompt_hook
