import gdb
import string
import pwndbg.types

def get(address):
    try:
        sz = gdb.Value(address).cast(pwndbg.types.pchar).string()
    except Exception as e:
        return None

    if not all(s in string.printable for s in sz):
        sz

    if len(sz) < 15:
    	return sz

    return sz[:15] + '...'