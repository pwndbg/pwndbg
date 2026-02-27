"""
Radare2 integration with r2pipe.
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
    import r2pipe as r2pipe_mod


@pwndbg.lib.cache.cache_until("start", "objfile")
def r2pipe() -> r2pipe_mod.open | Status:
    """
    Spawn and return a r2pipe handle for the current process file.

    This function requires a radare2 installation plus the r2pipe python
    library. The base address is automatically set for PIE when loading the
    binary.
    After opening the handle, the binary is automatically analyzed.

    If successful, returns the handle, otherwise returns a failing Status.
    """
    filename = pwndbg.aglib.proc.exe()
    if filename is None:
        return Status.fail("Could not find objfile to create a r2pipe for.")

    try:
        import r2pipe as r2pipe_mod
    except ImportError:
        return Status.coded_fail(
            ErrorCode.NO_IMPORT, "Could not import r2pipe python library. Is it installed?"
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
        r2 = r2pipe_mod.open(filename, flags)
    else:
        flags = ["-e", "io.cache=true"]
        exe = pwndbg.aglib.elf.exe()
        if pwndbg.aglib.elf.get_elf_info(filename).is_pie and exe is not None:
            flags.extend(["-B", hex(exe.address)])
        r2 = r2pipe_mod.open(filename, flags=flags)
    # LD -> list supported decompilers (e cmd.pdc=?)
    # Outputs for example: pdc\npdg
    if "pdg" not in str(r2.cmd("LD")).split("\n"):
        return Status.coded_fail(
            ErrorCode.NO_IMPORT, "radare2 plugin r2ghidra must be installed and available from r2."
        )
    return r2


def r2cmd(arguments: list[str]) -> str:
    """
    Return result of rizin command or error string.
    """
    r2 = r2pipe()
    if isinstance(r2, Status):
        # Since we got a status, it must be a failure.
        return message.error(r2.message)
    return str(r2.cmd(" ".join(arguments)))
