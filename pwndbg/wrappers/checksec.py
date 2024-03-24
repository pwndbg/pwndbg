from __future__ import annotations

from pwnlib.elf import ELF

def get_raw_out(local_path: str) -> str:
    elf = ELF(local_path)
    output = f"File: {elf.path}\n"
    output += f"Arch: {elf.arch}\n"
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
