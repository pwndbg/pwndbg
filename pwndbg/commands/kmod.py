"""
Displays information about loaded kernel modules. This command retrieves the list of kernel modules from the `modules` symbol
and displays information about each module. It can filter modules by a substring of their names if provided.
"""

from __future__ import annotations

import argparse

from tabulate import tabulate

import pwndbg.commands
from pwndbg.aglib.kernel.macros import for_each_entry

parser = argparse.ArgumentParser(description="Displays the loaded Linux kernel modules.")
parser.add_argument(
    "module_name", nargs="?", type=str, help="A module name substring to filter for"
)


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugInfo
def kmod(module_name=None) -> None:
    # Look up the address of the `modules` symbol, containing the head of the linked list of kernel modules
    modules_head = pwndbg.aglib.symbol.lookup_symbol_addr("modules")
    if modules_head is None:
        print(
            "The modules symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return

    print(f"Kernel modules address found at {modules_head:#x}.\n")

    try:
        table = []
        headers = ["Address", "Name", "Size", "Used by"]
        head = pwndbg.aglib.memory.get_typed_pointer_value("struct list_head", modules_head)

        # Iterate through the linked list of modules using for_each_entry
        for module in for_each_entry(head, "struct module", "list"):
            addr = int(module["mem"][0]["base"])
            name = pwndbg.aglib.memory.string(int(module["name"].address)).decode(
                "utf-8", errors="ignore"
            )

            # Calculate runtime memory footprint by summing sizes of MOD_TEXT, MOD_DATA, MOD_RODATA, MOD_RO_AFTER_INIT,
            # which excludes initialization sections that are freed after the module load. See `enum mod_mem_type` in kernel source.
            size = sum(int(module["mem"][i]["size"]) for i in range(4))
            uses = int(module["refcnt"]["counter"]) - 1

            # If module_name is provided, filter modules by name substring
            if not module_name or module_name in name:
                table.append([f"{addr:#x}", name, size, uses])

        print(tabulate(table, headers=headers, tablefmt="simple"))
    except Exception as e:
        print(
            f"An error occurred while retrieving kernel modules. It may not be supported by your kernel version or debug symbols: {e}"
        )
