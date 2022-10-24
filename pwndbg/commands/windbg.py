"""
Compatibility functionality for Windbg users.
"""

import argparse
import codecs
from builtins import str
from itertools import chain

import gdb

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.strings
import pwndbg.gdblib.symbol
import pwndbg.gdblib.typeinfo
import pwndbg.hexdump

parser = argparse.ArgumentParser(description="Starting at the specified address, dump N bytes.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to dump from."
)
parser.add_argument(
    "count",
    type=pwndbg.commands.AddressExpr,
    default=64,
    nargs="?",
    help="The number of bytes to dump.",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def db(address, count=64):
    """
    Starting at the specified address, dump N bytes
    (default 64).
    """
    return dX(1, address, count, repeat=db.repeat)


parser = argparse.ArgumentParser(description="Starting at the specified address, dump N words.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to dump from."
)
parser.add_argument(
    "count",
    type=pwndbg.commands.AddressExpr,
    default=32,
    nargs="?",
    help="The number of words to dump.",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def dw(address, count=32):
    """
    Starting at the specified address, dump N words
    (default 32).
    """
    return dX(2, address, count, repeat=dw.repeat)


parser = argparse.ArgumentParser(description="Starting at the specified address, dump N dwords.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to dump from."
)
parser.add_argument(
    "count",
    type=pwndbg.commands.AddressExpr,
    default=16,
    nargs="?",
    help="The number of dwords to dump.",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def dd(address, count=16):
    """
    Starting at the specified address, dump N dwords
    (default 16).
    """
    return dX(4, address, count, repeat=dd.repeat)


parser = argparse.ArgumentParser(description="Starting at the specified address, dump N qwords.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to dump from."
)
parser.add_argument(
    "count",
    type=pwndbg.commands.AddressExpr,
    default=8,
    nargs="?",
    help="The number of qwords to dump.",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def dq(address, count=8):
    """
    Starting at the specified address, dump N qwords
    (default 8).
    """
    return dX(8, address, count, repeat=dq.repeat)


parser = argparse.ArgumentParser(description="Starting at the specified address, hexdump.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to dump from."
)
parser.add_argument(
    "count",
    type=pwndbg.commands.AddressExpr,
    default=8,
    nargs="?",
    help="The number of bytes to hexdump.",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def dc(address, count=8):
    return pwndbg.commands.hexdump.hexdump(address=address, count=count)


def dX(size, address, count, to_string=False, repeat=False):
    """
    Traditionally, windbg will display 16 bytes of data per line.
    """

    lines = list(
        chain.from_iterable(
            pwndbg.hexdump.hexdump(
                data=None, size=size, count=count, address=address, repeat=repeat, dX_call=True
            )
        )
    )

    if not to_string and lines:
        print("\n".join(lines))

    return lines


def enhex(size, value):
    value = value & ((1 << 8 * size) - 1)
    x = "%x" % abs(value)
    x = x.rjust(size * 2, "0")
    return x


parser = argparse.ArgumentParser(description="Write hex bytes at the specified address.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to write to."
)
parser.add_argument("data", type=str, nargs="*", help="The bytes to write.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def eb(address, data):
    """
    Write hex bytes at the specified address.
    """
    return eX(1, address, data)


parser = argparse.ArgumentParser(description="Write hex words at the specified address.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to write to."
)
parser.add_argument("data", type=str, nargs="*", help="The words to write.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def ew(address, data):
    """
    Write hex words at the specified address.
    """
    return eX(2, address, data)


parser = argparse.ArgumentParser(description="Write hex dwords at the specified address.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to write to."
)
parser.add_argument("data", type=str, nargs="*", help="The dwords to write.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def ed(address, data):
    """
    Write hex dwords at the specified address.
    """
    return eX(4, address, data)


parser = argparse.ArgumentParser(description="Write hex qwords at the specified address.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to write to."
)
parser.add_argument("data", type=str, nargs="*", help="The qwords to write.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def eq(address, data):
    """
    Write hex qwords at the specified address.
    """
    return eX(8, address, data)


parser = argparse.ArgumentParser(description="Write a string at the specified address.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to write to."
)
parser.add_argument("data", type=str, help="The string to write.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def ez(address, data):
    """
    Write a character at the specified address.
    """
    return eX(1, address, data, hex=False)


parser = argparse.ArgumentParser(
    description="Write a string at the specified address."
)  # TODO Is eza just ez? If so just alias. I had trouble finding windbg documentation defining ez
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to write to."
)
parser.add_argument("data", type=str, help="The string to write.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def eza(address, data):
    """
    Write a string at the specified address.
    """
    return ez(address, data)


def eX(size, address, data, hex=True):
    """
    This relies on windbg's default hex encoding being enforced
    """
    if not data:
        print("Cannot write empty data into memory.")
        return

    if hex:
        # Early validation if all data is hex
        for string in data:
            if string.startswith("0x"):
                string = string[2:]

            if any(ch not in "0123456789abcdefABCDEF" for ch in string):
                print(
                    "Incorrect data format: it must all be a hex value (0x1234 or 1234, both interpreted as 0x1234)"
                )
                return

    writes = 0
    for i, string in enumerate(data):
        if hex:
            if string.startswith("0x"):
                string = string[2:]

            string = string.rjust(size * 2, "0")

            data = codecs.decode(string, "hex")
        else:
            data = string

        if pwndbg.gdblib.arch.endian == "little":
            data = data[::-1]

        try:
            pwndbg.gdblib.memory.write(address + (i * size), data)
            writes += 1
        except gdb.error:
            print("Cannot access memory at address %#x" % address)
            if writes > 0:
                print("(Made %d writes to memory; skipping further writes)" % writes)
            return


parser = argparse.ArgumentParser(description="Dump pointers and symbols at the specified address.")
parser.add_argument("addr", type=pwndbg.commands.HexOrAddressExpr, help="The address to dump from.")


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["kd", "dps", "dqs"]
)  # TODO are these really all the same? They had identical implementation...
@pwndbg.commands.OnlyWhenRunning
def dds(addr):
    """
    Dump pointers and symbols at the specified address.
    """
    return pwndbg.commands.telescope.telescope(addr)


da_parser = argparse.ArgumentParser()
da_parser.description = "Dump a string at the specified address."
da_parser.add_argument("address", type=pwndbg.commands.HexOrAddressExpr, help="Address to dump")
da_parser.add_argument("max", type=int, nargs="?", default=256, help="Maximum string length")


@pwndbg.commands.ArgparsedCommand(da_parser)
@pwndbg.commands.OnlyWhenRunning
def da(address, max):
    print("%x" % address, repr(pwndbg.gdblib.strings.get(address, max)))


ds_parser = argparse.ArgumentParser()
ds_parser.description = "Dump a string at the specified address."
ds_parser.add_argument("address", type=pwndbg.commands.HexOrAddressExpr, help="Address to dump")
ds_parser.add_argument("max", type=int, nargs="?", default=256, help="Maximum string length")


@pwndbg.commands.ArgparsedCommand(ds_parser)
@pwndbg.commands.OnlyWhenRunning
def ds(address, max):
    # We do change the max length to the default if its too low
    # because the truncated display is not that ideal/not the same as GDB's yet
    # (ours: "truncated ...", GDBs: "truncated "...)
    if max < 256:
        print("Max str len of %d too low, changing to 256" % max)
        max = 256

    string = pwndbg.gdblib.strings.get(address, max, maxread=4096)
    if string:
        print("%x %r" % (address, string))
    else:
        print(
            "Data at address can't be dereferenced or is not a printable null-terminated string or is too short."
        )
        print("Perhaps try: db <address> <count> or hexdump <address>")


@pwndbg.commands.ArgparsedCommand("List breakpoints.")
def bl():
    """
    List breakpoints
    """
    gdb.execute("info breakpoints")


parser = argparse.ArgumentParser(description="Disable the breakpoint with the specified index.")
parser.add_argument(
    "which", nargs="?", type=str, default="*", help="Index of the breakpoint to disable."
)


@pwndbg.commands.ArgparsedCommand(parser)
def bd(which="*"):
    """
    Disable the breakpoint with the specified index.
    """
    if which == "*":
        gdb.execute("disable breakpoints")
    else:
        gdb.execute("disable breakpoints %s" % which)


parser = argparse.ArgumentParser(description="Enable the breakpoint with the specified index.")
parser.add_argument(
    "which", nargs="?", type=str, default="*", help="Index of the breakpoint to enable."
)


@pwndbg.commands.ArgparsedCommand(parser)
def be(which="*"):
    """
    Enable the breakpoint with the specified index.
    """
    if which == "*":
        gdb.execute("enable breakpoints")
    else:
        gdb.execute("enable breakpoints %s" % which)


parser = argparse.ArgumentParser(description="Clear the breakpoint with the specified index.")
parser.add_argument(
    "which", nargs="?", type=str, default="*", help="Index of the breakpoint to clear."
)


@pwndbg.commands.ArgparsedCommand(parser)
def bc(which="*"):
    """
    Clear the breakpoint with the specified index.
    """
    if which == "*":
        gdb.execute("delete breakpoints")
    else:
        gdb.execute("delete breakpoints %s" % which)


parser = argparse.ArgumentParser(description="Set a breakpoint at the specified address.")
parser.add_argument("where", type=int, help="The address to break at.")


@pwndbg.commands.ArgparsedCommand(parser)
def bp(where):
    """
    Set a breakpoint at the specified address.
    """
    result = pwndbg.commands.fix(where)
    if result is not None:
        gdb.execute("break *%#x" % int(result))


parser = argparse.ArgumentParser(
    description="Starting at the specified address, disassemble N instructions."
)
parser.add_argument(
    "where", type=int, nargs="?", default=None, help="The address to disassemble at."
)
parser.add_argument(
    "n", type=int, nargs="?", default=5, help="The number of instructions to disassemble."
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def u(where=None, n=5, to_string=False):
    """
    Starting at the specified address, disassemble
    N instructions (default 5).
    """
    if where is None:
        where = pwndbg.gdblib.regs.pc
    return pwndbg.commands.nearpc.nearpc(where, n, to_string)


@pwndbg.commands.ArgparsedCommand("Print a backtrace (alias 'bt').")
@pwndbg.commands.OnlyWhenRunning
def k():
    """
    Print a backtrace (alias 'bt')
    """
    gdb.execute("bt")


parser = argparse.ArgumentParser(description="List the symbols nearest to the provided value.")
parser.add_argument(
    "value", type=int, nargs="?", default=None, help="The address you want the name of."
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def ln(value=None):
    """
    List the symbols nearest to the provided value.
    """
    if value is None:
        value = pwndbg.gdblib.regs.pc
    value = int(value)
    x = pwndbg.gdblib.symbol.get(value)
    if x:
        result = "(%#x)   %s" % (value, x)
        print(result)


# The three commands are aliases for `vmmap` and are set so in vmmap.py
# lm
# address
# vprot


@pwndbg.commands.ArgparsedCommand("Not be windows.")
@pwndbg.commands.OnlyWhenRunning
def peb():
    print("This isn't Windows!")


@pwndbg.commands.ArgparsedCommand("Windbg compatibility alias for 'continue' command.")
@pwndbg.commands.OnlyWhenRunning
def go():
    """
    Windbg compatibility alias for 'continue' command.
    """
    gdb.execute("continue")


@pwndbg.commands.ArgparsedCommand("Windbg compatibility alias for 'nextcall' command.")
@pwndbg.commands.OnlyWhenRunning
def pc():
    """
    Windbg compatibility alias for 'nextcall' command.
    """
    return pwndbg.commands.next.nextcall()
