"""
Rizin integration with rzpipe.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pwndbg.aglib.elf
import pwndbg.aglib.kernel
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.lib.cache
from pwndbg.color import message
from pwndbg.lib import ErrorCode
from pwndbg.lib import Status

if TYPE_CHECKING:
    import rzpipe as rzpipe_mod


@pwndbg.lib.cache.cache_until("start", "objfile")
def rzpipe() -> rzpipe_mod.open | Status:
    """
    Spawn and return a rzpipe handle for the current process file.
    This function requires a rizin installation plus the rzpipe python
    library. The base address is automatically set for PIE when loading the
    binary.
    After opening the handle, the binary is automatically analyzed.

    If successful, returns the handle, otherwise returns a failing Status.
    """
    filename = pwndbg.aglib.proc.exe()
    if filename is None:
        return Status.fail("Could not find objfile to create a rzpipe for")

    try:
        import rzpipe as rzpipe_mod
    except ImportError:
        return Status.coded_fail(
            ErrorCode.NO_IMPORT, "Could not import rzpipe python library. Is it installed?"
        )

    if pwndbg.aglib.qemu.is_qemu_kernel():
        flags = ["-e", "bin.cache=true", "-e", "bin.relocs.apply=true"]
        if (kbase := pwndbg.aglib.kernel.kbase()) and filename == pwndbg.aglib.proc.exe():
            urand = pwndbg.aglib.elf.get_vmlinux_unrand_base(filename)
            if urand is not None:
                flags.extend(
                    [
                        "-e",
                        "bin.baddr=" + hex(kbase - urand),
                    ]
                )
        rz = rzpipe_mod.open(filename, flags)
    else:
        flags = ["-e", "io.cache=true"]
        exe = pwndbg.aglib.elf.exe()
        if pwndbg.aglib.elf.get_elf_info(filename).is_pie and exe is not None:
            flags.extend(["-B", hex(exe.address)])
        rz = rzpipe_mod.open(filename, flags=flags)
    # Lc -> list core plugins
    if "ghidra" not in str(rz.cmd("Lc")):
        return Status.coded_fail(
            ErrorCode.NO_IMPORT, "rizin plugin rzghidra must be installed and available from rz."
        )
    return rz


def rzcmd(arguments: list[str]) -> str:
    """
    Return result of rizin command or error string.
    """
    rz = rzpipe()
    if isinstance(rz, Status):
        # Since we got a status, it must be a failure.
        return message.error(rz.message)
    return str(rz.cmd(" ".join(arguments)))
