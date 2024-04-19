"""
Provides values which would be available from /proc which
are not fulfilled by other modules and some process/gdb flow
related information.
"""

from __future__ import annotations

import functools
import sys
from types import ModuleType
from typing import Any
from typing import Callable
from typing import List
from typing import Optional
from typing import TypeVar

import gdb
from elftools.elf.relocation import Relocation

import pwndbg.gdblib.qemu
import pwndbg.lib.cache
import pwndbg.lib.memory

T = TypeVar("T")

pid: int
tid: int
thread_id: int
alive: bool
thread_is_stopped: bool
stopped_with_signal: bool
exe: str | None
binary_base_addr: int
binary_vmmap: tuple[pwndbg.lib.memory.Page, ...]
# dump_elf_data_section: tuple[int, int, bytes] | None
# dump_relocations_by_section_name: tuple[Relocation, ...] | None
# get_section_address_by_name: Callable[[str], int]
OnlyWhenRunning: Callable[[Callable[..., T]], Callable[..., T]]
OnlyWhenQemuKernel: Callable[[Callable[..., T]], Callable[..., T]]
OnlyWithArch: Callable[[List[str]], Callable[[Callable[..., T]], Callable[..., Optional[T]]]]


class module(ModuleType):
    @property
    def pid(self) -> int:
        # QEMU usermode emulation always returns 42000 for some reason.
        # In any case, we can't use the info.
        if pwndbg.gdblib.qemu.is_qemu_usermode():
            return pwndbg.gdblib.qemu.pid()

        i = gdb.selected_inferior()
        if i is not None:
            return i.pid
        return 0

    @property
    def tid(self) -> int:
        if pwndbg.gdblib.qemu.is_qemu_usermode():
            return pwndbg.gdblib.qemu.pid()

        i = gdb.selected_thread()
        if i is not None:
            return i.ptid[1]

        return self.pid

    @property
    def thread_id(self) -> int:
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
    def thread_is_stopped(self) -> bool:
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
    def exe(self) -> str | None:
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
    def binary_vmmap(self) -> tuple[pwndbg.lib.memory.Page, ...]:
        return tuple(p for p in pwndbg.gdblib.vmmap.get() if p.objfile == self.exe)

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def dump_elf_data_section(self) -> tuple[int, int, bytes] | None:
        """
        Dump .data section of current process's ELF file
        """
        return pwndbg.gdblib.elf.dump_section_by_name(self.exe, ".data", try_local_path=True)

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def dump_relocations_by_section_name(self, section_name: str) -> tuple[Relocation, ...] | None:
        """
        Dump relocations of a section by section name of current process's ELF file
        """
        return pwndbg.gdblib.elf.dump_relocations_by_section_name(
            self.exe, section_name, try_local_path=True
        )

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def get_section_address_by_name(self, section_name: str) -> int:
        """
        Find section address of current process by section name
        """
        out = pwndbg.gdblib.info.files()
        for line in out.splitlines():
            if line.endswith(f" is {section_name}"):
                return int(line.split()[0], 16)
        return 0

    def OnlyWhenRunning(self, func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*a: Any, **kw: Any) -> T:
            if self.alive:
                return func(*a, **kw)
            return None

        return wrapper

    def OnlyWhenQemuKernel(self, func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*a: Any, **kw: Any) -> T:
            if pwndbg.gdblib.qemu.is_qemu_kernel():
                return func(*a, **kw)
            return None

        return wrapper

    def OnlyWithArch(
        self, arch_names: List[str]
    ) -> Callable[[Callable[..., T]], Callable[..., Optional[T]]]:
        """Decorates function to work only with the specified archictectures."""
        for arch in arch_names:
            if arch not in pwndbg.gdblib.arch_mod.ARCHS:
                raise ValueError(
                    f"OnlyWithArch used with unsupported arch={arch}. Must be one of {', '.join(arch_names)}"
                )

        def decorator(function: Callable[..., T]) -> Callable[..., Optional[T]]:
            @functools.wraps(function)
            def _OnlyWithArch(*a: Any, **kw: Any) -> Optional[T]:
                if pwndbg.gdblib.arch.name in arch_names:
                    return function(*a, **kw)
                else:
                    return None

            return _OnlyWithArch

        return decorator


# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, "")
