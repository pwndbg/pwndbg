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
from typing import Optional
from typing import Tuple

import gdb
from elftools.elf.relocation import Relocation

import pwndbg.gdblib.qemu
import pwndbg.lib.cache
import pwndbg.lib.memory


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
    def thread_id(self):
        return gdb.selected_thread().num

    @property
    def alive(self) -> bool:
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
            `pwndbg.gdblib.file.get_proc_exe_file()`
            (This will call `pwndbg.gdblib.file.get_file(pwndbg.gdblib.proc.exe, try_local_path=True)`)
        """
        return gdb.current_progspace().filename

    @property
    @pwndbg.lib.cache.cache_until("start", "stop")
    def binary_base_addr(self) -> int:
        return self.binary_vmmap[0].start

    @property
    @pwndbg.lib.cache.cache_until("start", "stop")
    def binary_vmmap(self) -> Tuple[pwndbg.lib.memory.Page, ...]:
        return tuple(p for p in pwndbg.gdblib.vmmap.get() if p.objfile == self.exe)

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def dump_elf_data_section(self) -> Optional[Tuple[int, int, bytes]]:
        """
        Dump .data section of current process's ELF file
        """
        return pwndbg.gdblib.elf.dump_section_by_name(self.exe, ".data", try_local_path=True)

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def dump_relocations_by_section_name(
        self, section_name: str
    ) -> Optional[Tuple[Relocation, ...]]:
        """
        Dump relocations of a section by section name of current process's ELF file
        """
        return pwndbg.gdblib.elf.dump_relocations_by_section_name(
            self.exe, section_name, try_local_path=True
        )

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def get_data_section_address(self) -> int:
        """
        Find .data section address of current process.
        """
        out = pwndbg.gdblib.info.files()
        for line in out.splitlines():
            if line.endswith(" is .data"):
                return int(line.split()[0], 16)
        return 0

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def get_got_section_address(self) -> int:
        """
        Find .got section address of current process.
        """
        out = pwndbg.gdblib.info.files()
        for line in out.splitlines():
            if line.endswith(" is .got"):
                return int(line.split()[0], 16)
        return 0

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
