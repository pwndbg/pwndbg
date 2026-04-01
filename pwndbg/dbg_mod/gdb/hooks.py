from __future__ import annotations

from typing import Any

import gdb

import pwndbg
import pwndbg.aglib.arch_mod
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.strings
import pwndbg.aglib.typeinfo
import pwndbg.dbg_mod
import pwndbg.gdblib.events
from pwndbg.dbg_mod import EventHandlerPriority
from pwndbg.dbg_mod import EventType
from pwndbg.dbg_mod.gdb import BPWP_DEFERRED_DELETE
from pwndbg.dbg_mod.gdb import BPWP_DEFERRED_DISABLE
from pwndbg.dbg_mod.gdb import BPWP_DEFERRED_ENABLE

# TODO: Combine these `update_*` hook callbacks into one method


@pwndbg.dbg.event_handler(EventType.STOP)
def bpwp_process_deferred() -> None:
    for to_enable in BPWP_DEFERRED_ENABLE:
        to_enable.inner.enabled = True
    for to_disable in BPWP_DEFERRED_DISABLE:
        to_disable.inner.enabled = False
    for to_delete in BPWP_DEFERRED_DELETE:
        to_delete.inner.delete()
    bpwp_clear_deferred()


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.EXIT)
def bpwp_clear_deferred() -> None:
    for elem in BPWP_DEFERRED_DELETE:
        elem._clear()
    for elem in BPWP_DEFERRED_ENABLE:
        elem._clear()
    for elem in BPWP_DEFERRED_DISABLE:
        elem._clear()

    BPWP_DEFERRED_DELETE.clear()
    BPWP_DEFERRED_ENABLE.clear()
    BPWP_DEFERRED_DISABLE.clear()


def update_typeinfo() -> None:
    # Initialize the typing information in aglib.
    # Workaround for Rust stuff, see https://github.com/pwndbg/pwndbg/issues/855
    lang = gdb.execute("show language", to_string=True)
    if "rust" not in lang:
        restore_lang = None
    else:
        gdb.execute("set language c")
        if '"auto;' in lang:
            restore_lang = "auto"
        else:
            restore_lang = "rust"

    pwndbg.aglib.typeinfo.update()

    # Rust workaround part 2
    if restore_lang:
        gdb.execute(f"set language {restore_lang}")


@pwndbg.dbg.event_handler(EventType.NEW_MODULE, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
@pwndbg.dbg.event_handler(EventType.START, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
@pwndbg.dbg.event_handler(EventType.STOP, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
def update_arch_and_typeinfo() -> None:
    # It is important to update the typeinfo first because
    # pwndbg/dbg_mod/gdb/__init__.py:GDBProcess::arch() relies on it (maybe it shouldn't),
    # and arch_mod.update() relies on pwndbg.dbg.selected_inferior().arch().
    update_typeinfo()
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
    pwndbg.dbg_mod.number_of_stops_since_birth += 1


@pwndbg.dbg.event_handler(EventType.EXIT)
def on_exit() -> None:
    pwndbg.aglib.file.reset_remote_files()


import pwndbg.lib.cache
from pwndbg.lib.cache import CacheUntilEvent


def _on_inferior_call_post(event: Any) -> None:
    """Clear stop-caches after GDB completes an inferior function call.

    GDB does not fire ``gdb.events.stop`` for inferior function calls (e.g.
    ``call malloc(0x20)`` from the GDB prompt or ``gdb.execute('call ...')``
    from Python).  This means caches keyed on "stop" — most importantly vmmap —
    become stale when the inferior's memory layout changes during such calls
    (e.g. ``brk`` expanding the heap).

    By listening on ``gdb.events.inferior_call`` we can transparently invalidate
    these caches so that subsequent reads see up-to-date state.
    """
    if type(event).__name__ == "InferiorCallPostEvent":
        pwndbg.lib.cache.clear_cache(CacheUntilEvent.STOP)


# gdb.events.inferior_call was added in GDB 13.  On older versions we simply
# skip — the worst case is the pre-existing stale-cache behaviour.
if hasattr(gdb.events, "inferior_call"):
    gdb.events.inferior_call.connect(_on_inferior_call_post)


pwndbg.lib.cache.connect_clear_caching_events(
    {
        # Any cache that should be cleared when the program is stopped should also be cleared
        # if the user does an operation to modify memory or registers while the program is stopped.
        # We don't do this for the other events, because they hopefully don't change memory or
        # registers
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
        CacheUntilEvent.THREAD: (
            pwndbg.gdblib.events.event_handler_factory(
                gdb.events.new_thread, "THREAD", EventHandlerPriority.CACHE_CLEAR
            ),
        ),
        CacheUntilEvent.FOREVER: (),
    }
)


def init() -> None:
    """Calls all GDB hook functions that need to be called when GDB/pwndbg
    itself is loaded, as opposed to when an actual hook event occurs
    """
    update_arch_and_typeinfo()
    update_typeinfo()


init()
