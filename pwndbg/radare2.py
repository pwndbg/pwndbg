from __future__ import annotations

import pwndbg.aglib.elf
import pwndbg.lib.cache


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
    filename = pwndbg.dbg.selected_inferior().main_module_name()
    if not filename:
        raise Exception("Could not find objfile to create a r2pipe for")

    import r2pipe

    flags = ["-e", "io.cache=true"]
    if pwndbg.aglib.elf.get_elf_info(filename).is_pie and pwndbg.aglib.elf.exe():
        flags.extend(["-B", hex(pwndbg.aglib.elf.exe().address)])
    r2 = r2pipe.open(filename, flags=flags)
    r2.cmd("aaaa")
    return r2
