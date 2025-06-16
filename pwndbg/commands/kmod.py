"""
Displays information about loaded kernel modules. This command retrieves the list of kernel modules from the `modules` symbol
and displays information about each module. It can filter modules by a substring of their names if provided.
"""

from __future__ import annotations

import argparse

import pwndbg.commands
from pwndbg.aglib.kernel.macros import container_of

parser = argparse.ArgumentParser(description="Displays information about loaded kernel modules.")
parser.add_argument(
    "module_name", nargs="?", type=str, help="A module name substring to search for"
)


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugSyms
def kmod(module_name=None) -> None:
    # Look up the address of the `modules` symbol, containing the head of the linked list of kernel modules
    modules_head = pwndbg.aglib.symbol.lookup_symbol_addr("modules")
    if modules_head is None:
        print(
            "The modules symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return

    print(f"Kernel modules address found at {hex(modules_head)}.\n")

    try:
        print(f"{'Address':<18} {'Name':<19} {'Size':>8} {'Used by':<8}")
        head = pwndbg.aglib.memory.get_typed_pointer_value("struct list_head", modules_head)
        current = int(head["next"])

        # Iterate through the linked list of modules
        while current != modules_head:
            module = container_of(int(current), "struct module", "list")

            addr = hex(int(module["mem"][0]["base"]))
            name = pwndbg.aglib.memory.string(int(module["name"].address)).decode(
                "utf-8", errors="ignore"
            )
            size = sum(int(module["mem"][i]["size"]) for i in range(4))
            uses = int(module["refcnt"]["counter"]) - 1

            # If module_name is provided, filter modules by name substring
            if not module_name or module_name in name:
                print(f"{addr:<18} {name:<19} {size:>8} {uses:<8}")

            curr_module = pwndbg.aglib.memory.get_typed_pointer_value("struct list_head", current)
            next_addr = curr_module["next"]

            current = int(next_addr)

            if current == modules_head:
                break
    except Exception as e:
        print(
            f"An error occurred while retrieving kernel modules. It may not be supported by your kernel version or debug symbols: {e}"
        )
