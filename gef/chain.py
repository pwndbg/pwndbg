import gdb
import gef.color
import gef.enhance
import gef.memory
import gef.types
import gef.vmmap


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
            address = int(gef.memory.poi(gef.types.ppvoid, address))
        except gdb.MemoryError:
            break

    return result


def format(value):
    chain = get(value)

    # Enhance the last entry
    end   = [gef.enhance.enhance(chain[-1])]

    # Colorize the rest
    rest  = list(map(gef.color.get, chain[:-1]))

    return ' --> '.join(rest + end)