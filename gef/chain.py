import gdb
import gef.types
import gef.memory


def get(address, limit=5):
    """
    Recursively dereferences an address.

    Returns:
        A list containing ``address``, followed by up to ``limit`` valid pointers.
    """
    result = [int(address)]
    for i in range(limit):
        try:
            # Convert the current address to a void**
            address = gef.memory.poi(gef.types.ppvoid, address)

            # Ensure that it's a valid pointer by dereferencing it
            # *AND* attempting to get the resulting value.
            #
            # GDB will let you .dereference() anything, the int() throws
            # the gdb.MemoryError.
            int(address.dereference())

            # Save it off
            result.append(int(address))
        except gdb.MemoryError:
            break
    return result
