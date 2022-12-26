import pwndbg.gdblib.abi
import pwndbg.gdblib.events
import pwndbg.gdblib.file
import pwndbg.gdblib.memory
import pwndbg.gdblib.next
import pwndbg.gdblib.tls
import pwndbg.gdblib.typeinfo
from pwndbg.gdblib import arch_mod
from pwndbg.lib.memoize import reset_on_cont
from pwndbg.lib.memoize import reset_on_exit
from pwndbg.lib.memoize import reset_on_objfile
from pwndbg.lib.memoize import reset_on_prompt
from pwndbg.lib.memoize import reset_on_start
from pwndbg.lib.memoize import reset_on_stop
from pwndbg.lib.memoize import reset_on_thread
from pwndbg.lib.memoize import while_running

# TODO: Combine these `update_*` hook callbacks into one method


@pwndbg.gdblib.events.new_objfile
@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.stop
def update_typeinfo() -> None:
    pwndbg.gdblib.typeinfo.update()


@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.stop
@pwndbg.gdblib.events.new_objfile
def update_arch() -> None:
    arch_mod.update()


@pwndbg.gdblib.events.new_objfile
def reset_config() -> None:
    pwndbg.gdblib.kernel._kconfig = None


@pwndbg.gdblib.events.start
def on_start() -> None:
    pwndbg.gdblib.abi.update()
    pwndbg.gdblib.memory.update_min_addr()


@pwndbg.gdblib.events.exit
def on_exit() -> None:
    pwndbg.gdblib.tls.reset()
    pwndbg.gdblib.file.reset_remote_files()
    pwndbg.gdblib.next.clear_temp_breaks()


@pwndbg.gdblib.events.stop
def on_stop() -> None:
    pwndbg.gdblib.strings.update_length()


@pwndbg.gdblib.events.stop
@pwndbg.gdblib.events.mem_changed
@pwndbg.gdblib.events.reg_changed
def memoize_on_stop() -> None:
    reset_on_stop._reset()


@pwndbg.gdblib.events.before_prompt
def memoize_before_prompt() -> None:
    reset_on_prompt._reset()


@pwndbg.gdblib.events.cont
def memoize_on_cont() -> None:
    reset_on_cont._reset()


@pwndbg.gdblib.events.new_objfile
def memoize_on_new_objfile() -> None:
    reset_on_objfile._reset()


@pwndbg.gdblib.events.start
def memoize_on_start() -> None:
    while_running._start_caching()
    reset_on_start._reset()


@pwndbg.gdblib.events.exit
def memoize_on_exit() -> None:
    while_running._reset()
    reset_on_exit._reset()


@pwndbg.gdblib.events.thread
def memoize_on_new_thread() -> None:
    reset_on_thread._reset()


def init() -> None:
    """Calls all GDB hook functions that need to be called when GDB/pwndbg
    itself is loaded, as opposed to when an actual hook event occurs
    """
    update_arch()
    update_typeinfo()
    pwndbg.gdblib.abi.update()


init()
