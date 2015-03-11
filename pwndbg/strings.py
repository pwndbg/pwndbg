import gdb
import string
import pwndbg.types
import pwndbg.events

length = 15

@pwndbg.events.stop
def update_length():
    r"""
    Unfortunately there's not a better way to get at this info.

    >>> gdb.execute('show print elements', from_tty=False, to_string=True)
    'Limit on string chars or array elements to print is 21.\n'
    """
    global length
    message = gdb.execute('show print elements', from_tty=False, to_string=True)
    message = message.split()[-1]
    message = message.strip('.')
    length  = int(message)

def get(address):
    try:
        sz = gdb.Value(address).cast(pwndbg.types.pchar).string()
    except Exception as e:
        return None

    if not all(s in string.printable for s in sz.rstrip('\x00')):
        return None

    if len(sz) < length + 3:
    	return sz

    return sz[:length] + '...'