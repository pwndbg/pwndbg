"""
Provides values which would be available from /proc which
are not fulfilled by other modules and some process/gdb flow
related information.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TypeVar

from elftools.elf.relocation import Relocation
from typing_extensions import ParamSpec

import pwndbg
import pwndbg.aglib.qemu
import pwndbg.lib.arch
import pwndbg.lib.cache
import pwndbg.lib.memory

P = ParamSpec("P")
T = TypeVar("T")


def pid() -> int:
    return pwndbg.dbg.selected_inferior().pid()


def tid() -> int:
    return pwndbg.dbg.selected_thread().ptid()


def thread_id() -> int:
    return pwndbg.dbg.selected_thread().index()


def alive() -> bool:
    """
    Informs whether the process has a thread. However, note that it will
    still return True for a segfaulted thread. To detect that, consider
    using the `stopped_with_signal` method.
    """
    return pwndbg.dbg.selected_inferior().alive()


def is_core_file() -> bool:
    """
    Returns whether the loaded program is a corefile
    """
    return pwndbg.dbg.selected_inferior().is_core_file()


def stopped_with_signal() -> bool:
    """
    Returns whether the program has stopped with a signal

    Can be used to detect segfaults (but will also detect other signals)
    """
    return pwndbg.dbg.selected_inferior().stopped_with_signal()


@pwndbg.lib.cache.cache_until("objfile")
def exe() -> str | None:
    """
    Returns the executed file path.

    On remote targets, this path may not exist locally.

    If you need the locally referenced file use:
        `gdb.current_process().filename`
    """

    return pwndbg.dbg.selected_inferior().main_module_name()


@pwndbg.lib.cache.cache_until("start", "stop")
def binary_base_addr() -> int:
    return binary_vmmap()[0].start


@pwndbg.lib.cache.cache_until("start", "stop")
def binary_vmmap() -> tuple[pwndbg.lib.memory.Page, ...]:
    import pwndbg.aglib.vmmap

    return tuple(p for p in pwndbg.aglib.vmmap.get() if p.objfile == exe())


@pwndbg.lib.cache.cache_until("start", "objfile")
def dump_elf_data_section() -> tuple[int, int, bytes] | None:
    """
    Dump .data section of current process's ELF file
    """
    import pwndbg.aglib.elf

    return pwndbg.aglib.elf.section_by_name(exe(), ".data", try_local_path=True)


@pwndbg.lib.cache.cache_until("start", "objfile")
def dump_relocations_by_section_name(section_name: str) -> tuple[Relocation, ...] | None:
    """
    Dump relocations of a section by section name of current process's ELF file
    """
    import pwndbg.aglib.elf

    return pwndbg.aglib.elf.relocations_by_section_name(exe(), section_name, try_local_path=True)


@pwndbg.lib.cache.cache_until("start", "objfile")
def get_section_address_by_name(section_name: str) -> int:
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


def OnlyWhenRunning(func: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(func)
    def wrapper(*a: P.args, **kw: P.kwargs) -> T | None:
        if alive():
            return func(*a, **kw)
        return None

    return wrapper


def OnlyWhenQemuKernel(func: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(func)
    def wrapper(*a: P.args, **kw: P.kwargs) -> T | None:
        if pwndbg.aglib.qemu.is_qemu_kernel():
            return func(*a, **kw)
        return None

    return wrapper


def OnlyWithArch(arch_names: list[str]) -> Callable[[Callable[P, T]], Callable[P, T | None]]:
    """Decorates function to work only with the specified archictectures."""
    for arch in arch_names:
        if arch not in pwndbg.lib.arch.PWNDBG_SUPPORTED_ARCHITECTURES:
            raise ValueError(
                f"OnlyWithArch used with unsupported arch={arch}. Must be one of {', '.join(arch_names)}"
            )

    def decorator(function: Callable[P, T]) -> Callable[P, T | None]:
        @functools.wraps(function)
        def _OnlyWithArch(*a: P.args, **kw: P.kwargs) -> T | None:
            if pwndbg.aglib.arch.name in arch_names:
                return function(*a, **kw)
            return None

        return _OnlyWithArch

    return decorator
