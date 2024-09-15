"""
Provides values which would be available from /proc which
are not fulfilled by other modules and some process/gdb flow
related information.
"""

from __future__ import annotations

import functools
import sys
from types import ModuleType
from typing import Callable
from typing import List
from typing import Optional
from typing import Tuple
from typing import TypeVar

import gdb
from elftools.elf.relocation import Relocation
from typing_extensions import ParamSpec

import pwndbg.gdblib.info
import pwndbg.gdblib.qemu
import pwndbg.lib.cache
import pwndbg.lib.memory

P = ParamSpec("P")
T = TypeVar("T")

pid: int
tid: int
thread_id: int
alive: bool
thread_is_stopped: bool
stopped_with_signal: bool
exe: str | None
binary_base_addr: int
binary_vmmap: Tuple[pwndbg.lib.memory.Page, ...]
# dump_elf_data_section: Tuple[int, int, bytes] | None
# dump_relocations_by_section_name: Tuple[Relocation, ...] | None
# get_section_address_by_name: Callable[[str], int]


def OnlyWhenRunning(func: Callable[P, T]) -> Callable[P, T | None]: ...
def OnlyWhenQemuKernel(func: Callable[P, T]) -> Callable[P, T]: ...
def OnlyWithArch(
    arch_names: List[str],
) -> Callable[[Callable[..., T]], Callable[..., Optional[T]]]: ...


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
    @pwndbg.lib.cache.cache_until("objfile")
    def exe(self) -> str | None:
        """
        Returns the executed file path.

        On remote targets, this path may not exist locally.

        If you need the locally referenced file use:
            `gdb.current_process().filename`

        info proc exe is the only command to actually get the executed file path.
        The gdb `file` command overwrites all internal references, this includes:
        + `filename`
        + `executable_filename`
        + `symbol_file`
        + `objfiles`
        `run` executes the current file

        If you find a better solution please create a PR <3.

        Also refer to pwngdb.dbg.gdb.main_module_name
        """

        if not self.alive:
            return gdb.current_progspace().filename

        exe = gdb.execute("info proc exe", to_string=True)
        return exe[exe.find("exe = '") + 7 : exe.rfind("'")]

    @property
    @pwndbg.lib.cache.cache_until("start", "stop")
    def binary_base_addr(self) -> int:
        return self.binary_vmmap[0].start

    @property
    @pwndbg.lib.cache.cache_until("start", "stop")
    def binary_vmmap(self) -> Tuple[pwndbg.lib.memory.Page, ...]:
        import pwndbg.gdblib.vmmap

        return tuple(p for p in pwndbg.gdblib.vmmap.get() if p.objfile == self.exe)

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def dump_elf_data_section(self) -> Tuple[int, int, bytes] | None:
        """
        Dump .data section of current process's ELF file
        """
        import pwndbg.gdblib.elf

        return pwndbg.gdblib.elf.dump_section_by_name(self.exe, ".data", try_local_path=True)

    @pwndbg.lib.cache.cache_until("start", "objfile")
    def dump_relocations_by_section_name(self, section_name: str) -> Tuple[Relocation, ...] | None:
        """
        Dump relocations of a section by section name of current process's ELF file
        """
        import pwndbg.gdblib.elf

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

    def OnlyWhenRunning(self, func: Callable[P, T]) -> Callable[P, T | None]:
        @functools.wraps(func)
        def wrapper(*a: P.args, **kw: P.kwargs) -> T | None:
            if self.alive:
                return func(*a, **kw)
            return None

        return wrapper

    def OnlyWhenQemuKernel(self, func: Callable[P, T]) -> Callable[P, T | None]:
        @functools.wraps(func)
        def wrapper(*a: P.args, **kw: P.kwargs) -> T | None:
            if pwndbg.gdblib.qemu.is_qemu_kernel():
                return func(*a, **kw)
            return None

        return wrapper

    def OnlyWithArch(
        self, arch_names: List[str]
    ) -> Callable[[Callable[P, T]], Callable[P, Optional[T]]]:
        """Decorates function to work only with the specified archictectures."""
        for arch in arch_names:
            if arch not in pwndbg.gdblib.arch_mod.ARCHS:
                raise ValueError(
                    f"OnlyWithArch used with unsupported arch={arch}. Must be one of {', '.join(arch_names)}"
                )

        def decorator(function: Callable[P, T]) -> Callable[P, Optional[T]]:
            @functools.wraps(function)
            def _OnlyWithArch(*a: P.args, **kw: P.kwargs) -> Optional[T]:
                if pwndbg.gdblib.arch.name in arch_names:
                    return function(*a, **kw)
                else:
                    return None

            return _OnlyWithArch

        return decorator


# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, "")
