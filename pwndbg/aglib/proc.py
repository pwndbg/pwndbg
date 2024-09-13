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

from elftools.elf.relocation import Relocation
from typing_extensions import ParamSpec

import pwndbg.aglib.qemu
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
        if pwndbg.aglib.qemu.is_qemu_usermode():
            return pwndbg.aglib.qemu.pid()
        return pwndbg.dbg.selected_inferior().pid()

    @property
    def tid(self) -> int:
        if pwndbg.aglib.qemu.is_qemu_usermode():
            return pwndbg.aglib.qemu.pid()
        return pwndbg.dbg.selected_thread().ptid()

    @property
    def thread_id(self) -> int:
        return pwndbg.dbg.selected_thread().index()

    @property
    def alive(self) -> bool:
        """
        Informs whether the process has a thread. However, note that it will
        still return True for a segfaulted thread. To detect that, consider
        using the `stopped_with_signal` method.
        """
        return pwndbg.dbg.selected_inferior().alive()

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def exe(self) -> str | None:
        """
        Returns the executed file path.

        On remote targets, this path most definitly won't exist locally.

        If you need the locally referenced file use:
            `gdb.current_process().filename`
        """

        return pwndbg.dbg.selected_inferior().main_module_name()

    @property
    @pwndbg.lib.cache.cache_until("start", "stop")
    def binary_base_addr(self) -> int:
        return self.binary_vmmap[0].start

    @property
    @pwndbg.lib.cache.cache_until("start", "stop")
    def binary_vmmap(self) -> Tuple[pwndbg.lib.memory.Page, ...]:
        import pwndbg.aglib.vmmap

        return tuple(p for p in pwndbg.aglib.vmmap.get() if p.objfile == self.exe)

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
        selected = pwndbg.dbg.selected_inferior()
        main = selected.main_module_name()

        for address, size, section, module in selected.module_section_locations():
            if module != main:
                continue
            if section == section_name:
                return address

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
            if pwndbg.aglib.qemu.is_qemu_kernel():
                return func(*a, **kw)
            return None

        return wrapper

    def OnlyWithArch(
        self, arch_names: List[str]
    ) -> Callable[[Callable[P, T]], Callable[P, Optional[T]]]:
        """Decorates function to work only with the specified archictectures."""
        for arch in arch_names:
            if arch not in pwndbg.aglib.arch_mod.ARCHS:
                raise ValueError(
                    f"OnlyWithArch used with unsupported arch={arch}. Must be one of {', '.join(arch_names)}"
                )

        def decorator(function: Callable[P, T]) -> Callable[P, Optional[T]]:
            @functools.wraps(function)
            def _OnlyWithArch(*a: P.args, **kw: P.kwargs) -> Optional[T]:
                if pwndbg.aglib.arch.name in arch_names:
                    return function(*a, **kw)
                else:
                    return None

            return _OnlyWithArch

        return decorator


# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, "")
