from __future__ import annotations

import pwndbg.aglib.elf
import pwndbg.dbg
import pwndbg.lib.cache


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
    filename = pwndbg.dbg.selected_inferior().main_module_name()
    if not filename:
        raise Exception("Could not find objfile to create a rzpipe for")

    import rzpipe

    flags = ["-e", "io.cache=true"]
    if pwndbg.aglib.elf.get_elf_info(filename).is_pie and pwndbg.aglib.elf.exe():
        flags.extend(["-B", hex(pwndbg.aglib.elf.exe().address)])
    rz = rzpipe.open(filename, flags=flags)
    rz.cmd("aaaa")
    return rz
