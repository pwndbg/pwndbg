"""
Commands that help with debugging musl's allocator, mallocng.
"""

from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.heap.mallocng as mallocng
import pwndbg.aglib.memory as memory
import pwndbg.aglib.typeinfo as typeinfo
import pwndbg.color as C
import pwndbg.color.message as message
from pwndbg.aglib.heap.mallocng import mallocng as ng
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

    txt += (
        "Two other important definitions are " + C.bold("IB") + " and " + C.bold("UNIT") + ".\n\n"
    )

    txt += "// the aforementioned slot alignment.\n"
    txt += C.bold("#define UNIT 16\n")
    txt += "// the size of the in-band metadata.\n"
    txt += C.bold("#define IB 4\n\n")

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

    txt += f"""
### What slots look like

Unfortunately, musl doesn't provide a struct which describes the
slot's in-band metadata. It does however use consistent variable
names to describe the values saved in slots, so we will use those
as well. Check the {C.bold('enframe()')} function in the source, it is very
important.

{C.bold('idx')} is the index of the slot within its group. The {C.bold("stride")} of
a group is (generally) determined by the sizeclass as
{C.bold("UNIT * size_classes[meta.sizeclass]")}. {C.bold("start")} is the starting
address of the slot (the slot0, slot1, ... in the above diagram).
The start of a slot with index i is {C.bold("group.storage + i * stride")}.
The "nominal size" is the amount of memory the user requested with
their malloc() call, in the source it is also referred to as {C.bold("n")}.

For every slot in a group, the memory in [start - IB, start) contains
some metadata that we will call the "start header". For this reason,
the {C.bold("end")} of a slot is calculated as {C.bold("start + stride - IB")}. The
{C.bold("slack")} of a slot is calculated as {C.bold("(stride - n - IB) / UNIT")} and
describes the amount of unused memory within a slot.

To prevent double-frees and exploitation attempts, the mallocng
allocator performs "cycling" i.e. the actual start of user data
(the pointer returned by malloc) can be at some offset from the
{C.bold("start")} of the slot. The start of user data is called {C.bold("p")} and it
is also UNIT aligned. We will call the distance between {C.bold("p")} and
{C.bold("start")} the "cyclic offset" ({C.bold("off")} in code). When calculating
the cyclic offset, mallocng ensures {C.bold("off <= slack")}.

If a slot is in fact cycled, then that is stored in the start
header as {C.bold("off = *(uint16_t*)(start-2)")} and {C.bold("start[-3] = 7 << 5")}.
The {C.bold("start[-3]")} field acts as a flag.

For every slot, the memory in [p - IB, p) contains some metadata.
We will call this the "p header". If the slot is not cycled i.e.
{C.bold("start == p")}, then [start - IB, start) will contain the p header
fields and start[-3] >> 5 will *not* be 7.

The value in {C.bold("*(uint16_t*)(p-2)")} is the {C.bold("offset")} from the slot's
{C.bold("start")} to the start of the group (divided by UNIT). The value
in {C.bold("p[-4]")} is either 0 or 1 and describes if a "big offset" should
be used. It is usually zero and gets set to one only in some cases
in aligned_alloc(). If it is 1, the offset is to be calculated as
{C.bold("*(uint32_t *)(p - 8)")}.

{C.bold("p[-3]")} contains multiple pieces of information. If {C.bold("p[-3] == 0xFF")}
the slot is freed. Otherwise, the lower 5 bits of p[-3] describe
the index of the slot in its group: {C.bold("idx = p[-3] & 31")}. The top
3 bits desribed the {C.bold("reserved")} area size. This is the memory
between the end of user memory and {C.bold("end")} i.e. {C.bold("reserved = end - p - n")}.

We will call the value {C.bold("p[-3] >> 5")}, "hdr reserved" for "reserved as
specified in the p header". It can happen however, that the value
{C.bold("reserved = end - p - n")} is large and so doesn't fit in the three
bits in p[-3]. In this case "hdr reserved" will be strictly 5, which
denotes that we need to look at the slot's footer to read the actual
value of {C.bold("reserved")}. As a special case, if {C.bold("p[-3] >> 5 == 6")} that
doesn't describe the reserved size at all, but specifies that there
is a group nested inside this slot. {C.bold("p[-3] >> 5")} will never be 7,
contrary to {C.bold("start[-3] >> 5")}.

The "footer" of a slot is the third and final area of a slot's
memory where metadata is contained. This is the [end - 4, end)
area. It only contains the reserved size as
{C.bold("reserved = *(const uint32_t *)(end-4)")} when {C.bold("p[-3] >> 5 == 5")}.
    """

    print(txt)


def dump_group(group: mallocng.Group) -> str:
    try:
        # May fail on corrupt meta.
        group_size = group.group_size
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Error while reading meta: {e}"))
        print(C.bold("Cannot determine group size."))
        group_size = -1

    group_range = "@ " + C.memory.get(group.addr)
    if group_size != -1:
        group_range += " - " + C.memory.get(group.addr + group_size)

    pp = PropertyPrinter()
    pp.start_section("group", group_range)
    pp.set_padding(2)
    pp.add(
        [
            Property(name="meta", value=group.meta.addr, is_addr=True),
            Property(name="active_idx", value=group.active_idx),
            Property(name="storage", value=group.storage, is_addr=True, extra="start of slots"),
        ]
    )

    if group_size != -1:
        pp.write("---\n")
        pp.set_padding(3)
        pp.add(
            [
                Property(name="group size", value=group_size),
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
            Property(name="mem", value=meta.mem, is_addr=True, extra="the group"),
            Property(name="avail_mask", value=meta.avail_mask, extra=avail_binary),
            Property(name="freed_mask", value=meta.freed_mask, extra=freed_binary),
            Property(name="last_idx", value=meta.last_idx, extra="index of last slot"),
            Property(name="freeable", value=str(bool(meta.freeable))),
            Property(name="sizeclass", value=meta.sizeclass),
            Property(name="maplen", value=meta.maplen),
        ]
    )
    pp.write("---\n")
    pp.set_padding(3)
    pp.add(
        [
            Property(name="cnt", value=meta.cnt, extra="the number of slots"),
            Property(name="slot size", value=meta.slot_size, extra='aka "stride"'),
        ]
    )
    pp.end_section()

    output = pp.dump()

    if not meta.freeable:
        # When mapped object files contain unused memory, they are donated
        # to the heap. See https://elixir.bootlin.com/musl/v1.2.5/source/ldso/dynlink.c#L600
        # and https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/donate.c#L36 .
        # Only in this case is `meta.freeable = 0;`
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/donate.c#L25
        output += C.bold("\nGroup donated by ld as unused part of ")

        try:
            mapping = pwndbg.aglib.vmmap.find(mallocng.Group(meta.mem).addr)
        except pwndbg.dbg_mod.Error as e:
            print(message.error(f"Could not fetch parent group: {e}"))
            mapping = None

        if mapping is None:
            output += C.red("<cannot determine>")
        else:
            output += C.bold(f'"{mapping.objfile}"')

        output += C.bold(".\n")

    elif not meta.last_idx and meta.maplen:
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L177
        output += C.bold("\nGroup allocated with mmap().\n")
    else:
        output += C.bold("\nGroup nested in slot of another group")
        try:
            parent_group = mallocng.Slot(mallocng.Group(meta.mem).addr).group.addr
            output += " (" + C.memory.get(parent_group) + ")"
        except pwndbg.dbg_mod.Error as e:
            print(message.error(f"Could not fetch parent group: {e}"))
        output += C.bold(".\n")

    return output


parser = argparse.ArgumentParser(
    description="""
Dump information about a mallocng slot, given its user address.
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
    help="Print out all information. Including meta and group data.",
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MUSL,
    aliases=["ng-slotu"],
)
@pwndbg.commands.OnlyWhenRunning
def mallocng_slot_user(address: int, all: bool) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {address:#x} not readable."))
        return

    slot = mallocng.Slot(address)

    try:
        slot.preload()
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Error while reading slot: {e}"))
        return

    read_success: bool = True

    try:
        slot.group.preload()
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Error while reading group: {e}"))
        read_success = False

    try:
        slot.meta.preload()
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Error while reading meta: {e}"))
        read_success = False

    if not read_success:
        print(message.info("Only showing partial information."))
        all = False

    pp = PropertyPrinter()

    if not all:
        pp.start_section("slab")
        pp.set_padding(7)
        if read_success:
            pp.add(
                [
                    Property(name="group", value=slot.group.addr, is_addr=True),
                    Property(name="meta", value=slot.meta.addr, is_addr=True),
                ]
            )
        else:
            pp.add(
                [
                    Property(name="group", value=slot.group.addr, is_addr=True),
                ]
            )
        pp.end_section()

    if read_success:
        pp.start_section("general")
        pp.set_padding(2)
        pp.add(
            [
                Property(name="start", value=slot.start, is_addr=True),
                Property(name="user start", value=slot.p, is_addr=True, extra="aka `p`"),
                Property(name="end", value=slot.end, is_addr=True, extra="start + stride - 4"),
                Property(
                    name="stride", value=slot.meta.stride, extra="distance between adjacent slots"
                ),
                Property(name="user size", value=slot.user_size, extra='aka "nominal size", `n`'),
                Property(name="slack", value=slot.slack, extra="slot's unused memory / 0x10"),
            ]
        )
        pp.end_section()

    pp.start_section("in-band")
    pp.set_padding(4)

    reserved_extra = ["end - p - n", ""]
    if slot.reserved >= 5:
        reserved_extra[1] = "located near slot end"
        if slot.reserved == 6:
            reserved_extra.append("this slot is a nested group")
    else:
        reserved_extra[1] = "located in slot header"

    inband_group = [
        Property(name="offset", value=slot.offset, extra="distance to first slot / 0x10"),
        Property(name="index", value=slot.idx, extra="index of slot in its group"),
        Property(name="reserved", value=slot.reserved, extra=reserved_extra),
    ]

    if read_success:
        # While it is technically saved in-band, there is no way
        # for us to locate it without metadata.
        inband_group.append(
            Property(
                name="rnd-off",
                value=slot.internal_offset,
                extra="prevents double free, (p - start) / 0x10",
            ),
        )

    pp.add(inband_group)
    pp.end_section()

    pp.print()

    if all:
        print(dump_group(slot.group), end="")
        print(dump_meta(slot.meta), end="")


parser = argparse.ArgumentParser(
    description="""
Print out information about a mallocng group given the address of its meta.
    """,
)
parser.add_argument(
    "address",
    type=int,
    help="The address of the meta object.",
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MUSL,
    aliases=["ng-meta"],
)
@pwndbg.commands.OnlyWhenRunning
def mallocng_meta(address: int) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {address:#x} not readable."))
        return

    meta = mallocng.Meta(address)

    try:
        meta.preload()
    except pwndbg.dbg_mod.Error as e:
        print(message.error(str(e)))
        return

    try:
        group = mallocng.Group(meta.mem)
        group.preload()
        print(dump_group(group), end="")
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Failed loading group: {e}"))

    print(dump_meta(meta), end="")


parser = argparse.ArgumentParser(
    description="""
Print out information about a mallocng group at the given address.
    """,
)
parser.add_argument(
    "address",
    type=int,
    help="The address of the group object.",
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MUSL,
    aliases=["ng-group"],
)
@pwndbg.commands.OnlyWhenRunning
def mallocng_group(address: int) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {address:#x} not readable."))
        return

    group = mallocng.Group(address)

    try:
        group.preload()
    except pwndbg.dbg_mod.Error as e:
        print(message.error(str(e)))
        return

    print(dump_group(group), end="")

    try:
        meta = group.meta
        meta.preload()
        print(dump_meta(meta), end="")
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Failed loading meta: {e}"))
        return


parser = argparse.ArgumentParser(
    description="""
Find slot which contains the given address.

Returns the `start` of the slot. We say a slot 'contains'
an address if the address is in [start, start + stride).
    """,
)
parser.add_argument(
    "address",
    type=int,
    help="The address to look for.",
)
parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    help="Print out all information. Including meta and group data.",
)
parser.add_argument(
    "-m",
    "--metadata",
    action="store_true",
    help=(
        "If the given address falls onto some in-band metadata, return the slot which owns that metadata."
        " In other words, the containment check becomes [start - IB, end)."
    ),
)
parser.add_argument(
    "-s",
    "--shallow",
    action="store_true",
    help="Return the outermost slot hit without going deeper even if this slot contains a group.",
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MUSL,
    aliases=["ng-find"],
)
@pwndbg.commands.OnlyWhenRunning
def mallocng_find(
    address: int, all: bool = False, metadata: bool = False, shallow: bool = False
) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {hex(address)} not readable."))
        return

    ng.init_if_needed()

    slot_start = ng.containing(address, metadata, shallow)

    if slot_start == 0:
        print(message.info("No slot found containing that address."))
        return

    mallocng_slot_user(mallocng.Slot.from_start(slot_start).p, all=all)
