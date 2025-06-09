"""
Commands that help with debugging musl's allocator, mallocng.
"""

from __future__ import annotations

import argparse
from typing import Dict
from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.heap.mallocng as mallocng
import pwndbg.aglib.memory as memory
import pwndbg.aglib.typeinfo as typeinfo
import pwndbg.color as C
import pwndbg.color.message as message
from pwndbg.commands import CommandCategory
from pwndbg.lib.pretty_print import Property
from pwndbg.lib.pretty_print import PropertyPrinter


@pwndbg.commands.Command(
    "Gives a quick explanation of musl's mallocng allocator.",
    category=CommandCategory.MUSL,
    aliases=["ng-explain"],
)
def mallocng_explain() -> None:
    txt = (
        C.bold("mallocng")
        + ' is a slab allocator. The "unit of allocation" is called a '
        + C.bold("slot")
        + "\n"
    )
    txt += '(the equivalent of glibc\'s "chunk"). Slots are in 0x10 granularity and\n'
    txt += (
        "alignment. The slots are organized into objects called " + C.bold('"groups"') + " (the \n"
    )
    txt += "slabs). Each group is composed of slots of the same size. If a group is big\n"
    txt += "it is allocated using mmap, otherwise it is allocated as a slot of a larger\n"
    txt += "group.\n\n"

    txt += "Each group has some associated metadata. This metadata is stored in a separate\n"
    txt += "object called " + C.bold('"meta"') + ". Metas are allocated separately from groups in\n"
    txt += C.bold('"meta areas"') + " to make it harder to reach them during exploitation.\n\n"

    txt += "Here are the definitions of group, meta and meta_area.\n\n"

    txt += C.bold("struct group {\n")
    txt += "  // the metadata of this group\n"
    txt += C.bold("  struct meta *meta;\n")
    txt += "  unsigned char active_idx:5;\n"
    txt += "  char pad[UNIT - sizeof(struct meta *) - 1];\n"
    txt += "  // start of the slots array\n"
    txt += C.bold("  unsigned char storage[];\n")
    txt += C.bold("};\n\n")

    txt += C.bold("struct meta {\n")
    txt += "  // doubly linked list connecting meta's\n"
    txt += C.bold("  struct meta *prev, *next;\n")
    txt += "  // which group is this metadata for\n"
    txt += C.bold("  struct group *mem;\n")
    txt += "  // slot bitmap\n"
    txt += "  //   avail - slots which have not yet been allocated\n"
    txt += "  //   freed - free slots\n"
    txt += C.bold("  volatile int avail_mask, freed_mask;\n")
    txt += "  uintptr_t last_idx:5;\n"
    txt += "  uintptr_t freeable:1;\n"
    txt += "  // describes the size of the slots\n"
    txt += C.bold("  uintptr_t sizeclass:6;\n")
    txt += "  // if this group was mmaped, how many pages did we use?\n"
    txt += "  uintptr_t maplen:8*sizeof(uintptr_t)-12;\n"
    txt += C.bold("};\n\n")

    txt += C.bold("struct meta_area {\n")
    txt += "  uint64_t check;\n"
    txt += "  struct meta_area *next;\n"
    txt += "  int nslots;\n"
    txt += "  // start of the meta array\n"
    txt += C.bold("  struct meta slots[];\n")
    txt += C.bold("};\n\n")

    txt += "The allocator state is stored in the global `ctx` variable which is of\n"
    txt += "type `struct malloc_context`. It is accessible through the __malloc_context\n"
    txt += "symbol.\n\n"

    txt += C.bold("struct malloc_context {\n")
    txt += C.bold("  uint64_t secret;\n")
    txt += "#ifndef PAGESIZE\n"
    txt += "  size_t pagesize;\n"
    txt += "#endif\n"
    txt += "  int init_done;\n"
    txt += "  unsigned mmap_counter;\n"
    txt += C.bold("  struct meta *free_meta_head;\n")
    txt += C.bold("  struct meta *avail_meta;\n")
    txt += "  size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;\n"
    txt += C.bold("  struct meta_area *meta_area_head, *meta_area_tail;\n")
    txt += C.bold("  unsigned char *avail_meta_areas;\n")
    txt += '  // the "active" group for each sizeclass\n'
    txt += "  // it will be picked for allocation\n"
    txt += C.bold("  struct meta *active[48];\n")
    txt += "  size_t usage_by_class[48];\n"
    txt += "  uint8_t unmap_seq[32], bounces[32];\n"
    txt += "  uint8_t seq;\n"
    txt += "  uintptr_t brk;\n"
    txt += C.bold("};\n\n")

    txt += "Here is a diagram of how these components interact.\n\n"

    diag = """+-malloc_context--+
|                 |
| free_meta_head  |-----------------------> Points to a free meta which is connected
| avail_meta      |---------------+         to other free meta's via a doubly linked list.
| meta_area_head  |------------+  |
| active[48]      |---+        |  +-> Points to a not-yet-allocated meta.
|                 |   |        |      When it gets allocated, the next
|-----------------+   | 1/48   |      meta in the meta_area gets selected
                      |        |      i.e. avail_meta++ .
  Each size class has |        +-------------------------------------------+
  an "active" group.  +-------+                                            |
                              v                                            |
           +-meta--+       +-meta--+       +-meta--+                       |
           |       |       |       |       |       |                       |
  ...  <---| prev  |<------| prev  |------>| prev  |------>  ...           |
  ...  --->| next  |------>| next  |<------| next  |<------  ...           |
           | mem   |    +->| mem   |-+     | mem   |                       |
           |       |    |  |       | |     |       |                       v
           +-------+    |  +-------+ |     +-------+             +-meta_area----------------+
                        |            |  (yes these metas)        |                          |
                        |            |  (are in some meta_area)  | check (ctx.secret)       |
  +---------------------+            |                           | next                     |----> ...
  |                                  v                           | nslots                   |
  | +-group----------------------------------------+             | meta0                    |
  | |                                              |             |         Meta objects are |
  +-| meta (8)         | active_idx (1) | pad (7)  |             | meta1   stored here.     |
    | slot0                                        |             |                          |
    |                                              |             | ...                      |
    |                                              |             |                          |
    | slot1          Slots contain the actual      |             | meta(nslots-1)           |
    |                user data.                    |             |                          |
    |                                              |             +--------------------------+
    | slot2                                        |
    |                                              |
    | ...                                          |
    |                                              |
    | slot(cnt-1)                                  |
    |                                              |
    |                                              |
    +----------------------------------------------+
"""

    txt += diag

    # TODO: explain what a slot looks like.

    print(txt)


def dump_group(group: mallocng.Group) -> str:
    group_range = "@ " + C.memory.get(group.addr) + " - " + C.memory.get(group.addr + group.group_size)

    pp = PropertyPrinter()
    pp.start_section("group", group_range)
    pp.set_padding(2)
    pp.add(
        [
            Property(name="meta", value=group.meta.addr, is_addr=True),
            Property(name="active_idx", value=group.active_idx),
            Property(name="storage", value=group.storage, is_addr=True,
                     extra="(start of slots)"),
        ]
    )
    pp.write("---\n")
    pp.set_padding(3)
    pp.add(
        [
            Property(name="group size", value=group.group_size),
        ]
    )
    pp.end_section()
    return pp.dump()

def dump_meta(meta: mallocng.Meta) -> str:
    int_size = str(typeinfo.sint.sizeof * 8)
    avail_binary = "0b" + format(meta.avail_mask, f"0{int_size}b")
    freed_binary = "0b" + format(meta.freed_mask, f"0{int_size}b")

    pp = PropertyPrinter()
    pp.start_section("meta", "@ " + C.memory.get(meta.addr))
    pp.set_padding(2)
    pp.add(
        [
            Property(name="prev", value=meta.prev, is_addr=True),
            Property(name="next", value=meta.next, is_addr=True),
            Property(name="mem", value=meta.mem, is_addr=True,
                     extra="(the group)"),
            Property(name="avail_mask", value=meta.avail_mask,
                     extra=avail_binary),
            Property(name="freed_mask", value=meta.freed_mask,
                     extra=freed_binary),
            Property(name="last_idx", value=meta.last_idx,
                     extra="(index of last slot)"),
            Property(name="freeable", value=str(bool(meta.freeable))),
            Property(name="sizeclass", value=meta.sizeclass),
            Property(name="maplen", value=meta.maplen)
        ]
    )
    pp.write("---\n")
    pp.set_padding(3)
    pp.add(
        [
            Property(name="cnt", value=meta.cnt, extra="(the number of slots)"),
            Property(name="slot size", value=meta.slot_size, extra='(aka "stride")'),
        ]
    )
    pp.end_section()
    return pp.dump()


parser = argparse.ArgumentParser(
    description="""
Dump all information about a slot, given it's user address.
    """,
)
parser.add_argument(
    "address",
    type=int,
    help="The start of user memory. Referred to as `p` in the source.",
)
parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    help="Print out all information. Including meta and group data."
)

@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MUSL,
    aliases=["ng-uslot"],
)
def mallocng_user_slot(address: int, all: bool) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {hex(address)} not readable."))
        return

    slot = mallocng.Slot(address)

    pp = PropertyPrinter()

    if not all:
        pp.start_section("slab")
        pp.set_padding(7)
        pp.add(
            [
                Property(name="group", value=slot.group.addr, is_addr=True),
                Property(name="meta", value=slot.meta.addr, is_addr=True),
            ]
        )
        pp.end_section()

    pp.start_section("general")
    pp.set_padding(2)
    pp.add(
        [
            Property(name="start", value=slot.start, is_addr=True),
            Property(name="end", value=slot.end, is_addr=True),
            Property(name="stride", value=slot.meta.stride),
            Property(name="user start", value=slot.p, is_addr=True),
            Property(name="user size", value=slot.user_size),
        ]
    )
    pp.end_section()

    pp.start_section("in-band")
    pp.set_padding(4)
    pp.add(
        [
            Property(name="offset", value=slot.offset),
            Property(name="index", value=slot.idx),
            Property(name="reserved", value=slot.reserved),
        ]
    )
    pp.end_section()

    pp.print()

    if all:
        print(dump_group(slot.group), end="")
        print(dump_meta(slot.meta), end="")
