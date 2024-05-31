from __future__ import annotations

import contextlib
from typing import Iterator

import pwnlib.term.text
from pwnlib.elf import ELF

import pwndbg.color.message as M


@contextlib.contextmanager
def monkeypatch_pwnlib_term_text() -> Iterator[None]:
    # Note: It's kinda hacky to monkeypatch pwnlib.term.text like this, but I didn't find a better way to do it.
    # The patch is for here:
    # https://github.com/Gallopsled/pwntools/blob/f046fdd93e154bd892332f38cfbb518de130f1f2/pwnlib/elf/elf.py#L1999-L2001
    # This might break in the future, so need to update this patch when the implementation of pwnlib changes.
    pwnlib.term.text.red = M.error
    pwnlib.term.text.green = M.success
    pwnlib.term.text.yellow = M.warn
    yield
    del pwnlib.term.text.red
    del pwnlib.term.text.green
    del pwnlib.term.text.yellow


def get_raw_out(local_path: str) -> str:
    elf = ELF(local_path)
    # 10 is the magic number used in elf.checksec() to align the output.
    # https://github.com/Gallopsled/pwntools/blob/f046fdd93e154bd892332f38cfbb518de130f1f2/pwnlib/elf/elf.py#L2012
    # We might need to update this number if the implementation of elf.checksec() changes in the future.
    output = "File:".ljust(10) + elf.path + "\n"
    output += "Arch:".ljust(10) + elf.arch + "\n"
    with monkeypatch_pwnlib_term_text():
        output += elf.checksec()
    return output


def relro_status(local_path: str) -> str:
    relro = "No RELRO"
    out = get_raw_out(local_path)

    if "Full RELRO" in out:
        relro = "Full RELRO"
    elif "Partial RELRO" in out:
        relro = "Partial RELRO"

    return relro


def pie_status(local_path: str) -> str:
    pie = "No PIE"
    out = get_raw_out(local_path)

    if "PIE enabled" in out:
        pie = "PIE enabled"

    return pie
