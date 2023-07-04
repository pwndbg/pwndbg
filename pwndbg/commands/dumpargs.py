import argparse

import pwndbg.arguments
import pwndbg.chain
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.disasm

parser = argparse.ArgumentParser(description="Prints determined arguments for call instruction.")
parser.add_argument("-f", "--force", action="store_true", help="Force displaying of all arguments.")


@pwndbg.commands.ArgparsedCommand(parser, aliases=["args"])
@pwndbg.commands.OnlyWhenRunning
def dumpargs(force=False) -> None:
    args = (not force and call_args()) or all_args()

    if args:
        print("\n".join(args))
    else:
        print("Couldn't resolve call arguments from registers.")
        print(
            f"Detected ABI: {pwndbg.gdblib.arch.current} ({pwndbg.gdblib.arch.ptrsize * 8} bit) either doesn't pass arguments through registers or is not implemented. Maybe they are passed on the stack?"
        )


def call_args():
    """
    Returns list of resolved call argument strings for display.
    Attempts to resolve the target and determine the number of arguments.
    Should be used only when being on a call instruction.
    """
    results = []

    for arg, value in pwndbg.arguments.get(pwndbg.disasm.one()):
        code = arg.type != "char"
        pretty = pwndbg.chain.format(value, code=code)
        results.append("        %-10s %s" % (arg.name + ":", pretty))

    return results


def all_args():
    """
    Returns list of all argument strings for display.
    """
    results = []

    for name, value in pwndbg.arguments.arguments():
        results.append("%4s = %s" % (name, pwndbg.chain.format(value)))

    return results
