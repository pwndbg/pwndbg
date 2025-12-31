"""
Code that sets up hooks for LLDB events.
"""

from __future__ import annotations

import pwndbg
import pwndbg.aglib.arch_mod
import pwndbg.aglib.file
import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.aglib.strings
import pwndbg.aglib.typeinfo
import pwndbg.dbg_mod
import pwndbg.lib.cache
import pwndbg.lib.ctypes
from pwndbg.dbg_mod import EventHandlerPriority
from pwndbg.dbg_mod import EventType
from pwndbg.dbg_mod.lldb import LLDB
from pwndbg.lib.cache import CacheUntilEvent


@pwndbg.dbg.event_handler(EventType.NEW_MODULE, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
@pwndbg.dbg.event_handler(EventType.START, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
@pwndbg.dbg.event_handler(EventType.STOP, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
def update_arch_and_typeinfo() -> None:
    # Updating typeinfo first for consistency with GDB where it's required.
    pwndbg.aglib.typeinfo.update()
    pwndbg.aglib.arch_mod.update()


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def reset_config() -> None:
    pwndbg.aglib.kernel._kconfig = None


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def update_ctypes() -> None:
    pwndbg.lib.ctypes.update(str(pwndbg.aglib.arch.endian))


@pwndbg.dbg.event_handler(EventType.START)
def on_start() -> None:
    pwndbg.aglib.memory.update_min_addr()


@pwndbg.dbg.event_handler(EventType.STOP)
def on_stop() -> None:
    pwndbg.aglib.strings.update_length()
    pwndbg.dbg_mod.number_of_stops_since_birth += 1


@pwndbg.dbg.event_handler(EventType.EXIT)
def on_exit() -> None:
    pwndbg.aglib.file.reset_remote_files()


pwndbg.lib.cache.connect_clear_caching_events(
    {
        CacheUntilEvent.EXIT: (
            pwndbg.dbg.event_handler(EventType.EXIT, EventHandlerPriority.CACHE_CLEAR),
        ),
        CacheUntilEvent.OBJFILE: (
            pwndbg.dbg.event_handler(EventType.NEW_MODULE, EventHandlerPriority.CACHE_CLEAR),
        ),
        CacheUntilEvent.START: (
            pwndbg.dbg.event_handler(EventType.START, EventHandlerPriority.CACHE_CLEAR),
        ),
        CacheUntilEvent.STOP: (
            pwndbg.dbg.event_handler(EventType.STOP, EventHandlerPriority.CACHE_CLEAR),
            pwndbg.dbg.event_handler(EventType.MEMORY_CHANGED, EventHandlerPriority.CACHE_CLEAR),
            pwndbg.dbg.event_handler(EventType.REGISTER_CHANGED, EventHandlerPriority.CACHE_CLEAR),
        ),
        CacheUntilEvent.CONT: (
            pwndbg.dbg.event_handler(EventType.CONTINUE, EventHandlerPriority.CACHE_CLEAR),
            pwndbg.dbg.event_handler(EventType.MEMORY_CHANGED, EventHandlerPriority.CACHE_CLEAR),
            pwndbg.dbg.event_handler(EventType.REGISTER_CHANGED, EventHandlerPriority.CACHE_CLEAR),
        ),
        CacheUntilEvent.FOREVER: (),
    },
)

# As we don't have support for MEMORY_CHANGED, REGISTER_CHANGED, or NEW_THREAD
# yet, we disable these cache types, as we can't provide the same behavior for
# them as GDB can.
#
# TODO: Implement missing event types and re-enable the cache types that depend on them.
#
# FIXME: `stop` and `cont` have been enabled for performance reasons, but aren't 100% correct.
pwndbg.lib.cache.IS_CACHING_DISABLED_FOR = CacheUntilEvent.THREAD

should_show_context = False


@pwndbg.dbg.event_handler(EventType.STOP)
def renew_show_context():
    global should_show_context
    should_show_context = True


def prompt_hook():
    dbg: LLDB = pwndbg.dbg
    ctx_suspend_once = dbg.should_suspend_ctx
    global should_show_context
    if should_show_context and not ctx_suspend_once:
        pwndbg.commands.context.context()
        should_show_context = False
    dbg.should_suspend_ctx = False


# Install the prompt hook.
assert isinstance(pwndbg.dbg, LLDB)
dbg: LLDB = pwndbg.dbg

dbg.prompt_hook = prompt_hook
