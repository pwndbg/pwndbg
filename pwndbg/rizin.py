"""
Rizin integration with rzpipe.
"""

from __future__ import annotations

import pwndbg.aglib.elf
import pwndbg.dbg_mod
import pwndbg.lib.cache
from pwndbg.color import message


@pwndbg.lib.cache.cache_until("start", "objfile")
def rzpipe():
    """
    Spawn and return a rzpipe handle for the current process file.
    This function requires a rizin installation plus the rzpipe python
    library. The base address is automatically set for PIE when loading the
    binary.
    After opening the handle, the binary is automatically analyzed.
    Raises ImportError if rzpipe python library is not available.
    Raises Exception if anything goes fatally wrong.
    Returns a rzpipe.open handle.
    """
    filename = pwndbg.aglib.proc.exe()
    if not filename:
        raise Exception("Could not find objfile to create a rzpipe for")

    import rzpipe

    if pwndbg.aglib.qemu.is_qemu_kernel():
        flags = ["-e", "bin.cache=true", "-e", "bin.relocs.apply=true"]
        if (kbase := pwndbg.aglib.kernel.kbase()) and filename == pwndbg.aglib.proc.exe():
            flags.extend(
                [
                    "-e",
                    "bin.baddr=" + hex(kbase - pwndbg.aglib.elf.get_vmlinux_unrand_base(filename)),
                ]
            )
        rz = rzpipe.open(filename, flags)
    else:
        flags = ["-e", "io.cache=true"]
        if pwndbg.aglib.elf.get_elf_info(filename).is_pie and pwndbg.aglib.elf.exe():
            flags.extend(["-B", hex(pwndbg.aglib.elf.exe().address)])
        rz = rzpipe.open(filename, flags=flags)
    # Lc -> list core plugins
    if "ghidra" not in rz.cmd("Lc"):
        raise Exception("rizin plugin rzghidra must be installed and available from rz")
    return rz


def rzcmd(arguments) -> str:
    try:
        rz = rzpipe()
        return rz.cmd(" ".join(arguments))
    except ImportError:
        return message.error("Could not import rzpipe python library. Is it installed?")
    except Exception as e:
        return message.error(e)
    return ""
