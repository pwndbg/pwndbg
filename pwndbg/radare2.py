"""
Radare2 integration with r2pipe.
"""

from __future__ import annotations

import pwndbg.aglib.elf
import pwndbg.lib.cache
from pwndbg.color import message


@pwndbg.lib.cache.cache_until("start", "objfile")
def r2pipe():
    """
    Spawn and return a r2pipe handle for the current process file.

    This function requires a radare2 installation plus the r2pipe python
    library. The base address is automatically set for PIE when loading the
    binary.
    After opening the handle, the binary is automatically analyzed.

    Raises ImportError if r2pipe python library is not available.
    Raises Exception if anything goes fatally wrong.

    Returns a r2pipe.open handle.
    """
    filename = pwndbg.aglib.proc.exe()
    if not filename:
        raise Exception("Could not find objfile to create a r2pipe for")

    import r2pipe

    if pwndbg.aglib.qemu.is_qemu_kernel():
        flags = ["-e", "bin.cache=true", "-e", "bin.relocs.apply=true"]
        if (kbase := pwndbg.aglib.kernel.kbase()) and filename == pwndbg.aglib.proc.exe():
            flags.extend(
                [
                    "-e",
                    "bin.baddr=" + hex(kbase - pwndbg.aglib.elf.get_vmlinux_unrand_base(filename)),
                ]
            )
        r2 = r2pipe.open(filename, flags)
    else:
        flags = ["-e", "io.cache=true"]
        if pwndbg.aglib.elf.get_elf_info(filename).is_pie and pwndbg.aglib.elf.exe():
            flags.extend(["-B", hex(pwndbg.aglib.elf.exe().address)])
        r2 = r2pipe.open(filename, flags=flags)
    # LD -> list supported decompilers (e cmd.pdc=?)
    # Outputs for example: pdc\npdg
    if "pdg" not in r2.cmd("LD").split("\n"):
        raise Exception("radare2 plugin r2ghidra must be installed and available from r2")
    return r2


def r2cmd(arguments) -> str:
    try:
        r2 = r2pipe()
        return r2.cmd(" ".join(arguments))
    except ImportError:
        return message.error("Could not import r2pipe python library. Is it installed?")
    except Exception as e:
        return message.error(e)
    return ""
