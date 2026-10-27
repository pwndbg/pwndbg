"""
Debugger convenience variables that hold the base address of common memory
mappings, so `$libc + 0x1234` can be typed instead of `$base("libc") + 0x1234`.

The values are refreshed after every stop from the (already cached) memory
map, and cleared when the process starts or exits. A variable stays unset while
its mapping does not exist, for example `$heap` before the first `brk`.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import pwndbg
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.vmmap
import pwndbg.dbg_mod
from pwndbg.dbg_mod import EventType
from pwndbg.lib.memory import Page

# Matches libc.so.6, libc.so, libc-2.31.so and musl's libc.musl-x86_64.so.1.
_LIBC_RE = re.compile(r"^libc(\.musl-[\w.-]+\.so\.1|-\d[\d.]*\.so|\.so(\.\d+)*)$")
# Matches ld-linux-x86-64.so.2, ld-2.31.so, ld.so and ld-musl-x86_64.so.1.
_LD_RE = re.compile(r"^ld(-linux[\w.-]*|-musl-[\w.-]+|-\d[\d.]*)?\.so(\.\d+)*$")


def _basename_matches(regex: re.Pattern[str]) -> Callable[[str], bool]:
    return lambda objfile: regex.match(objfile.rsplit("/", 1)[-1]) is not None


# Variable name (without the `$`) -> predicate on a mapping's `objfile`.
_VARIABLES: dict[str, Callable[[str], bool]] = {
    "stack": lambda objfile: objfile == "[stack]",
    "heap": lambda objfile: objfile == "[heap]",
    "vdso": lambda objfile: objfile == "[vdso]",
    "vvar": lambda objfile: objfile == "[vvar]",
    "libc": _basename_matches(_LIBC_RE),
    "ld": _basename_matches(_LD_RE),
}

# What we last handed to the debugger, so a stop that changes nothing costs nothing.
# `None` means the variable is currently unset.
_current: dict[str, int | None] = {}


def _lowest_start(pages: tuple[Page, ...], matches: Callable[[str], bool]) -> int | None:
    starts = [page.start for page in pages if matches(page.objfile)]
    return min(starts) if starts else None


def _set(name: str, address: int | None) -> None:
    if _current.get(name) == address:
        return

    try:
        if address is None:
            # An expression of type void is how a convenience variable is unset.
            pwndbg.dbg.set_convenience_var(name, "(void)0", None)
        else:
            pwndbg.dbg.set_convenience_var(name, hex(address), "void*")
    except Exception:
        # Convenience variables are best effort: never break a stop over one.
        return

    _current[name] = address


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.EXIT)
def clear() -> None:
    for name in _VARIABLES:
        _set(name, None)
    _current.clear()


@pwndbg.dbg.event_handler(EventType.STOP)
def update() -> None:
    if not pwndbg.aglib.proc.alive():
        return
    if not pwndbg.dbg.selected_inferior().is_linux():
        return
    if pwndbg.aglib.qemu.is_qemu_kernel():
        # Kernel mappings have different names: that is a separate set of variables.
        return

    pages = pwndbg.aglib.vmmap.get()
    for name, matches in _VARIABLES.items():
        _set(name, _lowest_start(pages, matches))
