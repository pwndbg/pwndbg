import gdb

import pwndbg.gdblib.elf
import pwndbg.lib.memoize


@pwndbg.lib.memoize.reset_on_start
@pwndbg.lib.memoize.reset_on_objfile
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
    filename = gdb.current_progspace().filename
    if not filename:
        raise Exception("Could not find objfile to create a r2pipe for")

    import r2pipe

    flags = ["-e", "io.cache=true"]
    if pwndbg.gdblib.elf.get_elf_info(filename).is_pie and pwndbg.gdblib.elf.exe():
        flags.extend(["-B", hex(pwndbg.gdblib.elf.exe().address)])
    r2 = r2pipe.open(filename, flags=flags)
    r2.cmd("aaaa")
    return r2
