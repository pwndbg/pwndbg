import argparse

import pwndbg.chain
import pwndbg.commands
import pwndbg.enhance
import pwndbg.gdblib.file
import pwndbg.lib.which
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.color import message

parser = argparse.ArgumentParser(description="Show the state of the Global Offset Table")
parser.add_argument(
    "name_filter", help="Filter results by passed name.", type=str, nargs="?", default=""
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def got(name_filter=""):

    relro_status = pwndbg.wrappers.checksec.relro_status()
    pie_status = pwndbg.wrappers.checksec.pie_status()
    jmpslots = list(pwndbg.wrappers.readelf.get_jmpslots())
    if not len(jmpslots):
        print(message.error("NO JUMP_SLOT entries available in the GOT"))
        return

    if "PIE enabled" in pie_status:
        bin_base = pwndbg.gdblib.elf.exe().address

    relro_color = message.off
    if "Partial" in relro_status:
        relro_color = message.warn
    elif "Full" in relro_status:
        relro_color = message.on
    print(
        "\nGOT protection: %s | GOT functions: %d\n " % (relro_color(relro_status), len(jmpslots))
    )

    for line in jmpslots:
        address, info, rtype, value, name = line.split()[:5]

        if name_filter not in name:
            continue

        address_val = int(address, 16)

        if (
            "PIE enabled" in pie_status
        ):  # if PIE, address is only the offset from the binary base address
            address_val = bin_base + address_val

        got_address = pwndbg.gdblib.memory.pvoid(address_val)
        print(
            "[0x%x] %s -> %s" % (address_val, message.hint(name), pwndbg.chain.format(got_address))
        )
