"""
Compatibility functionality for Windbg users.
"""

from __future__ import annotations

import argparse
import codecs
from itertools import chain

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.strings
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.commands
from pwndbg.commands import CommandCategory

if pwndbg.dbg.is_gdblib_available():
    import gdb


def enhex(size, value):
    value = value & ((1 << 8 * size) - 1)
    x = "%x" % abs(value)
    x = x.rjust(size * 2, "0")
    return x


# `pwndbg.hexdump` imports `enhex` from this module, so we have to import it
# after it's been defined in order to avoid circular import errors.
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


parser = argparse.ArgumentParser(description="Write hex bytes at the specified address.")
parser.add_argument(
    "address", type=pwndbg.commands.HexOrAddressExpr, help="The address to write to."
)
parser.add_argument("data", type=str, nargs="*", help="The bytes to write.")


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
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


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
@pwndbg.commands.OnlyWhenRunning
def eza(address, data):
    """
    Write a string at the specified address.
    """
    return ez(address, data)


def eX(size, address, data, hex=True) -> None:
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

        if pwndbg.aglib.arch.endian == "little":
            data = data[::-1]

        try:
            pwndbg.aglib.memory.write(address + (i * size), data)
            writes += 1
        except pwndbg.dbg_mod.Error:
            print("Cannot access memory at address %#x" % address)
            if writes > 0:
                print("(Made %d writes to memory; skipping further writes)" % writes)
            return


parser = argparse.ArgumentParser(description="Dump pointers and symbols at the specified address.")
parser.add_argument("addr", type=pwndbg.commands.HexOrAddressExpr, help="The address to dump from.")


@pwndbg.commands.Command(
    parser, aliases=["kd", "dps", "dqs"], category=CommandCategory.WINDBG
)  # TODO are these really all the same? They had identical implementation...
@pwndbg.commands.OnlyWhenRunning
def dds(addr):
    """
    Dump pointers and symbols at the specified address.
    """
    return pwndbg.commands.telescope.telescope(addr)


da_parser = argparse.ArgumentParser(description="Dump a string at the specified address.")
da_parser.add_argument("address", type=pwndbg.commands.HexOrAddressExpr, help="Address to dump")
da_parser.add_argument("max", type=int, nargs="?", default=256, help="Maximum string length")


@pwndbg.commands.Command(da_parser, category=CommandCategory.WINDBG)
@pwndbg.commands.OnlyWhenRunning
def da(address, max) -> None:
    print("%x" % address, repr(pwndbg.aglib.strings.get(address, max)))


ds_parser = argparse.ArgumentParser(description="Dump a string at the specified address.")
ds_parser.add_argument("address", type=pwndbg.commands.HexOrAddressExpr, help="Address to dump")
ds_parser.add_argument("max", type=int, nargs="?", default=256, help="Maximum string length")


@pwndbg.commands.Command(ds_parser, category=CommandCategory.WINDBG)
@pwndbg.commands.OnlyWhenRunning
def ds(address, max) -> None:
    # We do change the max length to the default if its too low
    # because the truncated display is not that ideal/not the same as GDB's yet
    # (ours: "truncated ...", GDBs: "truncated "...)
    if max < 256:
        print("Max str len of %d too low, changing to 256" % max)
        max = 256

    string = pwndbg.aglib.strings.get(address, max, maxread=4096)
    if string:
        print(f"{address:x} {string!r}")
    else:
        print(
            "Data at address can't be dereferenced or is not a printable null-terminated string or is too short."
        )
        print("Perhaps try: db <address> <count> or hexdump <address>")


if pwndbg.dbg.is_gdblib_available():

    @pwndbg.commands.Command("List breakpoints.", category=CommandCategory.WINDBG)
    def bl() -> None:
        """
        List breakpoints
        """
        gdb.execute("info breakpoints")

    parser = argparse.ArgumentParser(description="Disable the breakpoint with the specified index.")
    parser.add_argument(
        "which", nargs="?", type=str, default="*", help="Index of the breakpoint to disable."
    )

    @pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
    def bd(which="*") -> None:
        """
        Disable the breakpoint with the specified index.
        """
        if which == "*":
            gdb.execute("disable breakpoints")
        else:
            gdb.execute(f"disable breakpoints {which}")

    parser = argparse.ArgumentParser(description="Enable the breakpoint with the specified index.")
    parser.add_argument(
        "which", nargs="?", type=str, default="*", help="Index of the breakpoint to enable."
    )

    @pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
    def be(which="*") -> None:
        """
        Enable the breakpoint with the specified index.
        """
        if which == "*":
            gdb.execute("enable breakpoints")
        else:
            gdb.execute(f"enable breakpoints {which}")

    parser = argparse.ArgumentParser(description="Clear the breakpoint with the specified index.")
    parser.add_argument(
        "which", nargs="?", type=str, default="*", help="Index of the breakpoint to clear."
    )

    @pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
    def bc(which="*") -> None:
        """
        Clear the breakpoint with the specified index.
        """
        if which == "*":
            gdb.execute("delete breakpoints")
        else:
            gdb.execute(f"delete breakpoints {which}")

    parser = argparse.ArgumentParser(description="Set a breakpoint at the specified address.")
    parser.add_argument("where", type=int, help="The address to break at.")

    @pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
    def bp(where) -> None:
        gdb.execute(f"break *{where:#x}")

    @pwndbg.commands.Command("Print a backtrace (alias 'bt').", category=CommandCategory.WINDBG)
    @pwndbg.commands.OnlyWhenRunning
    def k() -> None:
        """
        Print a backtrace (alias 'bt')
        """
        gdb.execute("bt")

    @pwndbg.commands.Command(
        "Windbg compatibility alias for 'continue' command.", category=CommandCategory.WINDBG
    )
    @pwndbg.commands.OnlyWhenRunning
    def go() -> None:
        """
        Windbg compatibility alias for 'continue' command.
        """
        gdb.execute("continue")


parser = argparse.ArgumentParser(description="List the symbols nearest to the provided value.")
parser.add_argument(
    "value", type=int, nargs="?", default=None, help="The address you want the name of."
)


@pwndbg.commands.Command(parser, category=CommandCategory.WINDBG)
@pwndbg.commands.OnlyWhenRunning
def ln(value: int = None) -> None:
    """
    List the symbols nearest to the provided value.
    """
    if value is None:
        value = pwndbg.aglib.regs.pc

    x = pwndbg.aglib.symbol.resolve_addr(value)
    if x:
        result = f"({value:#x})   {x}"
        print(result)


# The three commands are aliases for `vmmap` and are set so in vmmap.py
# lm
# address
# vprot


@pwndbg.commands.Command("Not be windows.", category=CommandCategory.WINDBG)
@pwndbg.commands.OnlyWhenRunning
def peb() -> None:
    print("This isn't Windows!")


@pwndbg.commands.Command(
    "Windbg compatibility alias for 'nextcall' command.", category=CommandCategory.WINDBG
)
@pwndbg.commands.OnlyWhenRunning
def pc():
    """
    Windbg compatibility alias for 'nextcall' command.
    """
    return pwndbg.commands.next.nextcall()
