"""
Find a chain of leaks given some starting address.
"""

import argparse
import queue

import gdb

import pwndbg.color.memory as M
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.gdblib.config
import pwndbg.gdblib.vmmap
from pwndbg.chain import c as C


# Used to recursively print the pointer chain.
# addr is a pointer. It is taken to be a child pointer.
# visited_map is a map of children -> (parent,parent_start)
def get_rec_addr_string(addr, visited_map):
    page = pwndbg.gdblib.vmmap.find(addr)
    arrow_right = C.arrow(" %s " % pwndbg.gdblib.config.chain_arrow_right)

    if page is not None:
        if addr not in visited_map:
            return ""

        parent_info = visited_map[addr]
        parent = parent_info[0]
        parent_base_addr = parent_info[1]
        if parent - parent_base_addr < 0:
            curText = hex(parent_base_addr) + hex(parent - parent_base_addr)
        else:
            curText = hex(parent_base_addr) + "+" + hex(parent - parent_base_addr)
        if parent_base_addr == addr:
            return ""
        return (
            get_rec_addr_string(parent_base_addr, visited_map)
            + M.get(parent_base_addr, text=curText)
            + arrow_right
        )
    else:
        return ""


# Useful for debugging. Prints a map of child -> (parent, parent_start)
def dbg_print_map(maps):
    for child, parent_info in maps.items():
        print("0x%x + (0x%x, 0x%x)" % (child, parent_info[0], parent_info[1]))


parser = argparse.ArgumentParser()
parser.description = """
Attempt to find a leak chain given a starting address.
Scans memory near the given address, looks for pointers, and continues that process to attempt to find leaks.

Example: leakfind $rsp --page_name=filename --max_offset=0x48 --max_depth=6. This would look for any chains of leaks \
that point to a section in filename which begin near $rsp, are never 0x48 bytes further from a known pointer, \
and are a maximum length of 6.
"""
parser.formatter_class = argparse.RawDescriptionHelpFormatter
parser.add_argument(
    "address", nargs="?", default="$sp", help="Starting address to find a leak chain from"
)
parser.add_argument(
    "-p",
    "--page_name",
    type=str,
    nargs="?",
    default=None,
    help="Substring required to be part of the name of any found pages",
)
parser.add_argument(
    "-o",
    "--max_offset",
    default=0x48,
    nargs="?",
    help="Max offset to add to addresses when looking for leak",
)
parser.add_argument(
    "-d", "--max_depth", default=0x4, nargs="?", help="Maximum depth to follow pointers to"
)
parser.add_argument(
    "-s",
    "--step",
    nargs="?",
    default=0x1,
    help="Step to add between pointers so they are considered. For example, if this is 4 it would only consider pointers at an offset divisible by 4 from the starting pointer",
)
parser.add_argument(
    "--negative_offset",
    nargs="?",
    default=0x0,
    help="Max negative offset to search before an address when looking for a leak",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def leakfind(
    address=None, page_name=None, max_offset=0x40, max_depth=0x4, step=0x1, negative_offset=0x0
):
    if address is None:
        raise argparse.ArgumentTypeError("No starting address provided.")
    foundPages = pwndbg.gdblib.vmmap.find(address)

    if not foundPages:
        raise argparse.ArgumentTypeError("Starting address is not mapped.")

    if not pwndbg.gdblib.memory.peek(address):
        raise argparse.ArgumentTypeError("Unable to read from starting address.")

    max_depth = int(max_depth)
    # Just warn the user that a large depth might be slow.
    # Probably worth checking offset^depth < threshold. Do this when more benchmarking is established.
    if max_depth > 8:
        print(message.warn("leakfind may take a while to run on larger depths."))

    stride = int(step)
    address = int(address)
    max_offset = int(max_offset)
    negative_offset = int(negative_offset)

    # The below map stores a map of child address->(parent_address,parent_start_address)
    # In the above tuple, parent_address is the exact address with a pointer to the child address.
    # parent_start_address is an address that a previous address pointed to.
    # We need to store both so that we can nicely create our leak chain.
    visited_map = {}
    visited_set = {int(address)}
    address_queue = queue.Queue()
    address_queue.put(int(address))
    depth = 0
    time_to_depth_increase = 0

    # Run a bfs
    # TODO look into performance gain from checking if an address is mapped before calling pwndbg.gdblib.memory.pvoid()
    # TODO also check using pwndbg.gdblib.memory.read for possible performance boosts.
    while address_queue.qsize() > 0 and depth < max_depth:
        if time_to_depth_increase == 0:
            depth = depth + 1
            time_to_depth_increase = address_queue.qsize()
        cur_start_addr = address_queue.get()
        time_to_depth_increase -= 1
        for cur_addr in range(
            cur_start_addr - negative_offset, cur_start_addr + max_offset, stride
        ):
            try:
                cur_addr &= pwndbg.gdblib.arch.ptrmask
                result = int(pwndbg.gdblib.memory.pvoid(cur_addr))
                if result in visited_map or result in visited_set:
                    continue
                visited_map[result] = (
                    cur_addr,
                    cur_start_addr,
                )  # map is of form child->(parent,parent_start)
                address_queue.put(result)
                visited_set.add(result)
            except gdb.error:
                # That means the memory was unmapped. Just skip it if we can't read it.
                break

    # A map of length->list of lines. Used to let us print in a somewhat nice manner.
    output_map = {}
    arrow_right = C.arrow(" %s " % pwndbg.gdblib.config.chain_arrow_right)

    for child in visited_map:
        child_page = pwndbg.gdblib.vmmap.find(child)
        if child_page is not None:
            if page_name is not None and page_name not in child_page.objfile:
                continue
            line = (
                get_rec_addr_string(child, visited_map)
                + M.get(child)
                + " "
                + M.get(child, text=child_page.objfile)
            )
            chain_length = line.count(arrow_right)
            if chain_length in output_map:
                output_map[chain_length].append(line)
            else:
                output_map[chain_length] = [line]

    # Output sorted by length of chain
    for chain_length in output_map:
        for line in output_map[chain_length]:
            print(line)

    if pwndbg.gdblib.qemu.is_qemu():
        print("\n[QEMU target detected - leakfind result might not be accurate; see `help vmmap`]")
