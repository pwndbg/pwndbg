from __future__ import annotations

import argparse

from pwnlib.util.cyclic import cyclic

import pwndbg.aglib.memory
import pwndbg.aglib.vmmap
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Spray memory with cyclic() generated values")
parser.add_argument("addr", help="Address to spray", type=int)
parser.add_argument(
    "length",
    help="Length of byte sequence, when unspecified sprays until the end of vmmap which address belongs to",
    type=int,
    nargs="?",
    default=0,
)
parser.add_argument(
    "--value",
    help="Value to spray memory with, when prefixed with '0x' treated as hex string encoded big-endian",
    type=str,
    required=False,
)
parser.add_argument(
    "-x",
    "--only-funcptrs",
    help="Spray only addresses whose values points to executable pages",
    action="store_true",
)
parser.add_argument(
    "--page",
    help="Spray only pointers that point to a specific vmmap page (accepts page name like '[heap]' or address)",
    type=str,
    required=False,
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def spray(addr, length, value, only_funcptrs, page) -> None:
    # Resolve target pages for filtering if --page is specified
    target_pages = []
    if page:
        # Try to parse as address first (hex or decimal)
        try:
            page_addr = int(page, 16) if page.startswith("0x") else int(page)
        except ValueError:
            page_addr = None

        if page_addr is not None:
            target_page = pwndbg.aglib.vmmap.find(page_addr)
            if target_page is None:
                print(message.error(f"Invalid address {page}: can't find vmmap containing it"))
                return
            target_pages = [target_page]
        else:
            # Not an address, treat as page name with partial matching
            # Support both exact match and partial match (e.g., 'heap' matches '[heap]')
            matching_pages = []
            for p in pwndbg.aglib.vmmap.get():
                if page in p.objfile:
                    matching_pages.append(p)

            if len(matching_pages) == 0:
                print(message.error(f"Invalid page name '{page}': can't find matching vmmap page"))
                return
            elif len(matching_pages) == 1:
                target_pages = matching_pages
            else:
                # Multiple matches found - spray to all of them
                target_pages = matching_pages
                print(
                    message.notice(
                        f"Found {len(matching_pages)} pages matching '{page}', will spray pointers to any of them"
                    )
                )

    if length == 0:
        spray_page = pwndbg.aglib.vmmap.find(addr)
        if spray_page is None:
            print(
                message.error(
                    f"Invalid address {addr}: can't find vmmap containing it to determine the spray length"
                )
            )
            return
        length = spray_page.end - int(addr)

    value_bytes = b""

    if value:
        if value.startswith("0x"):
            value_bytes = int(value, 16).to_bytes((len(value[2:]) + 1) // 2, byteorder="big")
        else:
            value_bytes = bytes(value, "utf-8")

        value_length = len(value_bytes)
        value_bytes = value_bytes * (int(length) // value_length)

        if length % value_length != 0:
            value_bytes += value_bytes[: (length % value_length)]
    else:
        value_bytes = cyclic(length, n=pwndbg.aglib.arch.ptrsize)

    try:
        if only_funcptrs or target_pages:
            mem = pwndbg.aglib.memory.read(addr, length)

            addresses_written = 0
            ptrsize = pwndbg.aglib.arch.ptrsize
            for i in range(0, len(mem) - (length % ptrsize), ptrsize):
                ptr_candidate = pwndbg.aglib.arch.unpack(mem[i : i + ptrsize])
                ptr_page = pwndbg.aglib.vmmap.find(ptr_candidate)

                # Apply filters
                should_spray = True

                # Check if pointer points to executable page (if --only-funcptrs is set)
                if only_funcptrs:
                    should_spray = should_spray and (ptr_page is not None and ptr_page.execute)

                # Check if pointer points to any of the target pages (if --page is set)
                if target_pages:
                    page_match = False
                    for target_page in target_pages:
                        if (
                            ptr_page is not None
                            and ptr_page.start == target_page.start
                            and ptr_page.end == target_page.end
                        ):
                            page_match = True
                            break
                    should_spray = should_spray and page_match

                if should_spray:
                    pwndbg.aglib.memory.write(addr + i, value_bytes[i : i + ptrsize])
                    addresses_written += 1

            # Generate appropriate message based on filters used
            if only_funcptrs and target_pages:
                if len(target_pages) == 1:
                    print(
                        message.notice(
                            f"Overwritten {addresses_written} function pointers pointing to {target_pages[0].objfile}"
                        )
                    )
                else:
                    print(
                        message.notice(
                            f"Overwritten {addresses_written} function pointers pointing to {len(target_pages)} matching pages"
                        )
                    )
            elif only_funcptrs:
                print(message.notice(f"Overwritten {addresses_written} function pointers"))
            elif target_pages:
                if len(target_pages) == 1:
                    print(
                        message.notice(
                            f"Overwritten {addresses_written} pointers pointing to {target_pages[0].objfile}"
                        )
                    )
                else:
                    print(
                        message.notice(
                            f"Overwritten {addresses_written} pointers pointing to {len(target_pages)} matching pages"
                        )
                    )
        else:
            pwndbg.aglib.memory.write(addr, value_bytes)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(e))
