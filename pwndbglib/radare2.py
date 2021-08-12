import gdb

import pwndbglib.elf
import pwndbglib.memoize


@pwndbglib.memoize.reset_on_new_base_address
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
        raise Exception('Could not find objfile to create a r2pipe for')

    import r2pipe
    flags = ['-e', 'io.cache=true']
    if pwndbglib.elf.get_elf_info(filename).is_pie and pwndbglib.elf.exe():
        flags.extend(['-B', hex(pwndbglib.elf.exe().address)])
    r2 = r2pipe.open(filename, flags=flags)
    r2.cmd("aaaa")
    return r2
