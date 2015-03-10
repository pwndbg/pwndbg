import gdb
import pwndbg.color
import pwndbg.enhance
import pwndbg.memory
import pwndbg.types
import pwndbg.vmmap


def get(address, limit=5):
    """
    Recursively dereferences an address.

    Returns:
        A list containing ``address``, followed by up to ``limit`` valid pointers.
    """
    result = []
    for i in range(limit):
        result.append(address)
        try:
            address = int(pwndbg.memory.poi(pwndbg.types.ppvoid, address))
        except gdb.MemoryError:
            break

    return result


def format(value):
    chain = get(value)

    # Enhance the last entry
    end   = [pwndbg.enhance.enhance(chain[-1])]

    # Colorize the rest
    rest  = list(map(pwndbg.color.get, chain[:-1]))

    return ' --> '.join(rest + end)