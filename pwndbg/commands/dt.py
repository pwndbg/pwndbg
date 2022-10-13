import argparse

import pwndbg.color
import pwndbg.commands
import pwndbg.gdblib.dt
import pwndbg.gdblib.vmmap

parser = argparse.ArgumentParser()
parser.description = """
    Dump out information on a type (e.g. ucontext_t).

    Optionally overlay that information at an address.
    """
parser.add_argument("typename", type=str, help="The name of the structure being dumped.")
parser.add_argument(
    "address", type=int, nargs="?", default=None, help="The address of the structure."
)


@pwndbg.commands.ArgparsedCommand(parser)
def dt(typename, address=None):
    """
    Dump out information on a type (e.g. ucontext_t).

    Optionally overlay that information at an address.
    """
    if address is not None:
        address = pwndbg.commands.fix(address)
    print(pwndbg.gdblib.dt.dt(typename, addr=address))
