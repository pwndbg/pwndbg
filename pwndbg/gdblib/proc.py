"""
Provides values which would be available from /proc which
are not fulfilled by other modules and some process/gdb flow
related information.
"""

import functools
import sys
from types import ModuleType
from typing import Any
from typing import Callable

import gdb

import pwndbg.gdblib.qemu
import pwndbg.lib.memoize


class module(ModuleType):
    @property
    def pid(self):
        # QEMU usermode emulation always returns 42000 for some reason.
        # In any case, we can't use the info.
        if pwndbg.gdblib.qemu.is_qemu_usermode():
            return pwndbg.gdblib.qemu.pid()

        i = gdb.selected_inferior()
        if i is not None:
            return i.pid
        return 0

    @property
    def tid(self):
        if pwndbg.gdblib.qemu.is_qemu_usermode():
            return pwndbg.gdblib.qemu.pid()

        i = gdb.selected_thread()
        if i is not None:
            return i.ptid[1]

        return self.pid

    @property
    def alive(self):
        """
        Informs whether the process has a thread. However, note that it will
        still return True for a segfaulted thread. To detect that, consider
        using the `stopped_with_signal` method.
        """
        return gdb.selected_thread() is not None

    @property
    def thread_is_stopped(self):
        """
        This detects whether selected thread is stopped.
        It is not stopped in situations when gdb is executing commands
        that are attached to a breakpoint by `command` command.

        For more info see issue #229 ( https://github.com/pwndbg/pwndbg/issues/299 )
        :return: Whether gdb executes commands attached to bp with `command` command.
        """
        return gdb.selected_thread().is_stopped()

    @property
    def stopped_with_signal(self) -> bool:
        """
        Returns whether the program has stopped with a signal

        Can be used to detect segfaults (but will also detect other signals)
        """
        return "It stopped with signal " in gdb.execute("info program", to_string=True)

    @property
    def exe(self):
        """
        Returns the debugged file name.

        On remote targets, this may be prefixed with "target:" string.
        See this by executing those in two terminals:
        1. gdbserver 127.0.0.1:1234 /bin/ls
        2. gdb -ex "target remote :1234" -ex "pi pwndbg.gdblib.proc.exe"

        If you need to process the debugged file use:
            `pwndbg.gdblib.file.get_file(pwndbg.gdblib.proc.exe)`
        """
        return gdb.current_progspace().filename

    def OnlyWhenRunning(self, func):
        @functools.wraps(func)
        def wrapper(*a, **kw):
            if self.alive:
                return func(*a, **kw)

        return wrapper


OnlyWhenRunning: Callable[[Any], Any]
# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, "")
