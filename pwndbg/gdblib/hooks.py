from __future__ import annotations

import gdb

import pwndbg
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.strings
import pwndbg.aglib.typeinfo
import pwndbg.gdblib.events
from pwndbg.aglib import arch_mod as arch_mod_aglib
from pwndbg.dbg import EventType

# TODO: Combine these `update_*` hook callbacks into one method


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.STOP)
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


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.STOP)
@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def update_arch() -> None:
    arch_mod_aglib.update()


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
        # Any cache that should be cleared when the program is stopped should also be cleared
        # if the user does an operation to modify memory or registers while the program is stopped.
        # We don't do this for the other events, because they hopefully don't change memory or
        # registers
        "stop": (
            pwndbg.gdblib.events.stop,
            pwndbg.gdblib.events.mem_changed,
            pwndbg.gdblib.events.reg_changed,
        ),
        "exit": (pwndbg.gdblib.events.exit,),
        "objfile": (pwndbg.gdblib.events.new_objfile,),
        "start": (pwndbg.gdblib.events.start,),
        "cont": (
            pwndbg.gdblib.events.cont,
            pwndbg.gdblib.events.mem_changed,
            pwndbg.gdblib.events.reg_changed,
        ),
        "thread": (pwndbg.gdblib.events.thread,),
        "prompt": (pwndbg.gdblib.events.before_prompt,),
        "forever": (),
    },
    priority=pwndbg.gdblib.events.HandlerPriority.CACHE_CLEAR,
)


def init() -> None:
    """Calls all GDB hook functions that need to be called when GDB/pwndbg
    itself is loaded, as opposed to when an actual hook event occurs
    """
    update_arch()
    update_typeinfo()


init()
