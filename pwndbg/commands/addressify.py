from __future__ import annotations

from typing import Any

import gdb

import pwndbg.color.message as M
import pwndbg.commands


class AddressifyFunction(gdb.Function):
    # GDB standalone function to convert a hex string to little-endian address and return the address.

    def __init__(self) -> None:
        super().__init__("addressify")

    def invoke(self, *args: gdb.Value) -> gdb.Value:
        if not args or len(args) != 1:
            raise gdb.GdbError("addressify expects a single hex string argument.")

        arg = args[0].string()
        address = addressify_common(arg)
        return gdb.Value(address)


AddressifyFunction()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def addressify(*args: Any) -> None:
    # Pwndbg command to convert hex string to little-endian address and print the result.
    if len(args) == 1 and args[0] in ("-h", "--help"):
        print("Usage: addressify <hex_string>")
        print("Converts a space-separated hex string to a little-endian address.")
        print("Example: addressify 00 70 75 c1 cd ef 59 00")
        return

    combined_args = "".join(args).replace(" ", "")
    result = addressify_common(combined_args)
    print(M.success(f"{hex(result)}"))


def addressify_common(arg: str) -> int:
    arg = "".join(filter(str.isalnum, arg))
    if len(arg) % 2 != 0:
        raise gdb.GdbError("Hex string must contain an even number of characters.")
    try:
        big_endian_num = int(arg, 16)
        num_bytes = big_endian_num.to_bytes((len(arg) + 1) // 2, byteorder="big")
        little_endian_num = int.from_bytes(num_bytes, byteorder="little")
    except ValueError as e:
        raise gdb.GdbError(f"Invalid hex string: {e}")
    return little_endian_num
