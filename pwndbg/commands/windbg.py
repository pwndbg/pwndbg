import codecs
import gdb
import math
import pwndbg.arch
import pwndbg.commands
import pwndbg.memory
import pwndbg.types


def get_type(size):
    return {
    1: pwndbg.types.uint8,
    2: pwndbg.types.uint16,
    4: pwndbg.types.uint32,
    8: pwndbg.types.uint64,
    }[size]

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def db(address, count=64):
    return dX(1, int(address), int(count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dw(address, count=32):
    return dX(2, int(address), int(count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dd(address, count=16):
    return dX(4, int(address), int(count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dq(address, count=8):
    return dX(8, int(address), int(count))


def dX(size, address, count, to_string=False):
    """
    Traditionally, windbg will display 16 bytes of data per line.
    """
    values = []
    type   = get_type(size)
    for i in range(count):
        try:
            gval = pwndbg.memory.poi(type, address + i * size)
            values.append(int(gval))
        except gdb.MemoryError:
            break

    n_rows = math.ceil(count * size / float(16))
    row_sz = int(16 / size)
    rows   = [values[i*row_sz:(i+1)*row_sz] for i in range(n_rows)]
    lines  = []

    for i, row in enumerate(rows):
        line = [enhex(pwndbg.arch.ptrsize, address + i+16)]
        for value in row:
            line.append(enhex(size, value))
        lines.append(' '.join(line))

    if not to_string:
        print('\n'.join(lines))

    return lines

def enhex(size, value):
    x = "%x" % abs(value)
    x = x.rjust(size * 2, '0')
    return x


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def eb(address, *data):
    return eX(1, address, data)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def ew(address, *data):
    return eX(2, address, data)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def ed(address, *data):
    return eX(4, address, data)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def eq(address, *data):
    return eX(8, address, data)


def eX(size, address, data):
    """
    This relies on windbg's default hex encoding being enforced
    """
    address = pwndbg.commands.fix(address)

    for i,bytestr in enumerate(data):
        bytestr = bytestr.rjust(size*2, '0')
        data    = codecs.decode(bytestr, 'hex')
        pwndbg.memory.write(address + (i * size), data)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dds(*a):
    return pwndbg.commands.telescope.telescope(*a)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dps(*a):
    return pwndbg.commands.telescope.telescope(*a)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dqs(*a):
    return pwndbg.commands.telescope.telescope(*a)


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def da(address):
    print("%x" % address, pwndbg.string.get(address))

