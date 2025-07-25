from __future__ import annotations

import argparse
import signal
import string
from typing import Optional

from pwnlib.util.cyclic import cyclic
from pwnlib.util.cyclic import cyclic_find

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.commands
import pwndbg.lib.regs
from pwndbg.color import message
from pwndbg.commands import CommandCategory


class TimeoutException(Exception):
    """Custom exception for signal-based timeouts."""

    pass


def detect_register_patterns(alphabet, length, timeout) -> None:
    if not pwndbg.aglib.proc.alive:
        print(message.error("Error: Process is not running."))
        return

    ptr_size = pwndbg.aglib.arch.ptrsize
    endian = pwndbg.aglib.arch.endian
    found_patterns = []

    def alarm_handler(signum, frame):
        raise TimeoutException

    original_handler = signal.signal(signal.SIGALRM, alarm_handler)

    current_arch_name = pwndbg.aglib.arch.name
    register_set = pwndbg.lib.regs.reg_sets[current_arch_name]
    all_register_names = register_set.all

    for reg_name in all_register_names:
        value = pwndbg.aglib.regs[reg_name]
        if value is None:
            continue

        try:
            signal.alarm(timeout)
            value_bytes = value.to_bytes(ptr_size, endian)
            offset = cyclic_find(value_bytes, alphabet=alphabet, n=length)
            if offset != -1:
                found_patterns.append((reg_name, value, offset))
        except TimeoutException:
            found_patterns.append((reg_name, value, "SKIPPED (Timeout)"))
        finally:
            signal.alarm(0)

        if pwndbg.aglib.memory.is_readable_address(value):
            try:
                signal.alarm(timeout)
                mem_value = pwndbg.aglib.memory.read(value, length)
                offset = cyclic_find(mem_value, alphabet=alphabet, n=length)
                if offset != -1:
                    found_patterns.append((f"{reg_name}->", value, offset))
            except TimeoutException:
                found_patterns.append((f"{reg_name}->", value, "<Timeout>"))
            finally:
                signal.alarm(0)

    # Restore the original signal handler
    signal.signal(signal.SIGALRM, original_handler)

    if not found_patterns:
        print(message.notice("No cyclic patterns found."))
        return

    max_reg_width = 2 + max(max(len(reg) for reg, _, _ in found_patterns), 10)
    max_val_width = 2 + max(len(hex(val)) for _, val, _ in found_patterns)

    print(f"{'Register':<{max_reg_width}} {'Value':<{max_val_width}} {'Offset'}")
    print(f"{'----------':<{max_reg_width}} {'------------------':<{max_val_width}} {'------'}")
    for reg, val, off in found_patterns:
        print(f"{reg:<{max_reg_width}} {val:<#{max_val_width}x} {off}")


parser = argparse.ArgumentParser(description="Cyclic pattern creator/finder.")

parser.add_argument(
    "-a",
    "--alphabet",
    metavar="charset",
    default=string.ascii_lowercase,
    type=str.encode,
    help="The alphabet to use in the cyclic pattern",
)

parser.add_argument(
    "-n",
    "--length",
    metavar="length",
    type=int,
    help="Size of the unique subsequences (defaults to the pointer size for the current arch)",
)

parser.add_argument(
    "-t",
    "--timeout",
    metavar="seconds",
    type=int,
    default=2,
    help="Timeout in seconds for --detect",
)

group = parser.add_mutually_exclusive_group(required=False)
group.add_argument(
    "-l",
    "-o",
    "--offset",
    "--lookup",
    dest="lookup",
    metavar="lookup_value",
    type=str,
    help="Do a lookup instead of printing the sequence (accepts constant values as well as expressions)",
)

group.add_argument(
    "-d",
    "--detect",
    action="store_true",
    help="Detect cyclic patterns in registers (Immediate values and memory pointed to by registers)",
)

group.add_argument(
    "count",
    type=int,
    nargs="?",
    default=100,
    help="Number of characters to print from the sequence (default: print the entire sequence)",
)

parser.add_argument(
    "filename",
    type=str,
    help="Name (path) of the file to save the cyclic pattern to",
    nargs="?",
)


@pwndbg.commands.Command(parser, command_name="cyclic", category=CommandCategory.MISC)
def cyclic_cmd(
    alphabet, length: Optional[int], lookup, detect, count=100, filename="", timeout=2
) -> None:
    if length is None:
        length = pwndbg.aglib.arch.ptrsize

    if detect:
        detect_register_patterns(alphabet, length, timeout)
        return

    if lookup:
        lookup = pwndbg.commands.fix(lookup, sloppy=True)

        if isinstance(lookup, (pwndbg.dbg_mod.Value, int)):
            lookup = int(lookup).to_bytes(length, pwndbg.aglib.arch.endian)
        elif isinstance(lookup, str):
            lookup = bytes(lookup, "utf-8")

        if len(lookup) != length:
            print(
                message.error(
                    f"Lookup pattern must be {length} bytes (use `-n <length>` to lookup pattern of different length)"
                )
            )
            return

        hexstr = "0x" + lookup.hex()
        print(
            message.notice(
                f"Finding cyclic pattern of {length} bytes: {str(lookup)} (hex: {hexstr})"
            )
        )

        if any(c not in alphabet for c in lookup):
            print(message.error("Pattern contains characters not present in the alphabet"))
            return

        offset = cyclic_find(lookup, alphabet, length)

        if offset == -1:
            print(message.error("Given lookup pattern does not exist in the sequence"))
        else:
            print(message.success(f"Found at offset {offset}"))
    else:
        count = int(count)
        sequence = cyclic(count, alphabet, length)

        if not filename:
            print(sequence.decode())
        else:
            with open(filename, "wb") as f:
                f.write(sequence)
                print(f"Written a cyclic sequence of length {count} to file {filename}")
