import gdb
import pwndbg.elf
import pwndbg.ida
import pwndbg.memoize
import pwndbg.memory
import pwndbg.stack


@pwndbg.memoize.reset_on_objfile
def get(address):
    """
    Retrieve the textual name for a symbol
    """
    # Fast path
    if address < pwndbg.memory.MMAP_MIN_ADDR:
        return ''

    # Don't look up stack addresses
    if pwndbg.stack.find(address):
        return ''

    # This sucks, but there's not a GDB API for this.
    result = gdb.execute('info symbol %#x' % int(address), to_string=True, from_tty=False)

    if result.startswith('No symbol'):
        address = int(address)
        exe     = pwndbg.elf.exe()
        if exe:
            exe_map = pwndbg.vmmap.find(exe.address)
            if exe_map and address in exe_map:
                res =  pwndbg.ida.Name(address) or pwndbg.ida.GetFuncOffset(address)
                return res or ''

    # Expected format looks like this:
    # main in section .text of /bin/bash
    # main + 3 in section .text of /bin/bash
    # system + 1 in section .text of /lib/x86_64-linux-gnu/libc.so.6
    # No symbol matches system-1.
    a, b, c, _ = result.split(None, 3)


    if b == '+':
        return "%s+%s" % (a, c)
    if b == 'in':
        return a

    return ''

@pwndbg.memoize.reset_on_objfile
def address(symbol):
    if isinstance(symbol, (int,long)):
        return symbol

    try:
        result = gdb.execute('info address %s' % symbol, to_string=True, from_tty=False)
        result = result.split()
        address = next(r for r in result if r.startswith('0x'))
        return int(address, 0)
    except gdb.error:
        return None
