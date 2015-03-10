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
    try:
        chain = get(value)

        # Enhance the last entry
        # If there are no pointers (e.g. eax = 0x41414141), then enhance
        # the only element there is.
        if len(chain) == 1:
            enhanced = pwndbg.enhance.enhance(chain[-1])

        # Otherwise, the last element in the chain is the non-pointer value.
        # We want to enhance the last pointer value.
        else:
            enhanced = pwndbg.enhance.enhance(chain[-2])

        end = [enhanced]
        
        # Colorize the rest
        rest  = list(map(pwndbg.color.get, chain[:-1]))

        return ' --> '.join(rest + end)
    except:
        import pdb
        pdb.post_mortem()