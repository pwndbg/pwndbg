"""
Commands that help with debugging musl's allocator, mallocng.
"""

from __future__ import annotations

import argparse
import string

import pwndbg
import pwndbg.aglib.proc
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
import pwndbg.color.memory as mem_color
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.lib.config
from pwndbg import color
from pwndbg import config
from pwndbg.aglib import memory
from pwndbg.aglib import typeinfo
from pwndbg.aglib.heap import mallocng
from pwndbg.aglib.heap.mallocng import ng
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib.pretty_print import Property
from pwndbg.lib.pretty_print import from_properties

search_on_fail = config.add_param(
    "ng-search-on-fail",
    True,
    "let the ng-slot* commands search the heap if necessary",
    help_docstring="""
For freed, avail(able) and corrupted slots, it may be
impossible to recover the start of the group and meta.

When this option is set to True, the ng-slotu and ng-slots
commands will search the heap to try to find the correct meta/group.
    """,
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
    scope=pwndbg.lib.config.Scope.heap,
)

state_alloc_color = color.BLUE
state_alloc_color_alt = color.CYAN
state_freed_color = color.RED
state_freed_color_alt = color.LIGHT_RED
state_avail_color = color.GRAY
state_avail_color_alt = color.LIGHT_GRAY


def get_slot_color(state: mallocng.SlotState, last_color: str = "") -> str:
    match state:
        case mallocng.SlotState.ALLOCATED:
            if last_color == state_alloc_color:
                return state_alloc_color_alt
            return state_alloc_color
        case mallocng.SlotState.FREED:
            if last_color == state_freed_color:
                return state_freed_color_alt
            return state_freed_color
        case mallocng.SlotState.AVAIL:
            if last_color == state_avail_color:
                return state_avail_color_alt
            return state_avail_color


def get_colored_slot_state(ss: mallocng.SlotState) -> str:
    return color.colorize(ss.value, get_slot_color(ss))


def get_colored_slot_state_short(ss: mallocng.SlotState) -> str:
    match ss:
        case mallocng.SlotState.ALLOCATED:
            return color.colorize("U", state_alloc_color)
        case mallocng.SlotState.FREED:
            return color.colorize("F", state_freed_color)
        case mallocng.SlotState.AVAIL:
            return color.colorize("A", state_avail_color)


def dump_group(group: mallocng.Group) -> str:
    try:
        # May fail on corrupt meta.
        group_size = group.group_size
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Error while reading meta: {e}"))
        print(color.bold("Cannot determine group size."))
        group_size = -1

    group_range = "@ " + mem_color.get(group.addr)
    if group_size != -1:
        group_range += " - " + mem_color.get(group.addr + group_size)

    output = from_properties(
        "group",
        [
            Property(name="meta", value=group.meta.addr, is_addr=True),
            Property(name="active_idx", value=group.active_idx),
            Property(name="storage", value=group.storage, is_addr=True, extra="start of slots"),
        ],
        preamble=group_range,
    )

    if group_size != -1:
        output += "---\n"
        output += from_properties(
            "",
            [
                Property(name="group size", value=group_size),
            ],
        )

    return output


def dump_meta(meta: mallocng.Meta, focus_slot: int | None = None) -> str:
    """
    Arguments:
        meta: the meta to dump
        focus_slot: the index of the slot to highlight in the slot statuses list
    """
    int_size = str(typeinfo.sint.sizeof * 8)
    avail_binary = "0b" + format(meta.avail_mask, f"0{int_size}b")
    freed_binary = "0b" + format(meta.freed_mask, f"0{int_size}b")

    output = from_properties(
        "meta",
        [
            Property(name="prev", value=meta.prev, is_addr=True),
            Property(name="next", value=meta.next, is_addr=True),
            Property(name="mem", value=meta.mem, is_addr=True, extra="the group"),
            Property(name="avail_mask", value=meta.avail_mask, extra=avail_binary),
            Property(name="freed_mask", value=meta.freed_mask, extra=freed_binary),
            Property(
                name="last_idx",
                value=meta.last_idx,
                alt_value=f"cnt: {meta.cnt:#x}",
                extra="index of last slot",
            ),
            Property(name="freeable", value=str(bool(meta.freeable))),
            Property(name="sizeclass", value=meta.sizeclass, alt_value=f"stride: {meta.stride:#x}"),
            Property(name="maplen", value=meta.maplen),
        ],
        preamble="@ " + mem_color.get(meta.addr),
    )

    if meta.is_donated:
        output += color.bold("\nGroup donated by ld as unused part of ")

        mapping = pwndbg.aglib.vmmap.find(meta.mem)

        if mapping is None:
            output += color.red("<cannot determine>")
        else:
            output += color.bold(f'"{mapping.objfile}"')

        output += color.bold(".\n")

    elif meta.is_mmaped:
        output += color.bold("\nGroup allocated with mmap().\n")
    else:
        assert meta.is_nested
        output += color.bold("\nGroup nested in slot of another group")
        try:
            parent_group = meta.parent_group()
            assert parent_group != -1
            output += " (" + mem_color.get(parent_group) + ")"
        except pwndbg.dbg_mod.Error as e:
            print(message.error(f"Could not fetch parent group: {e}"))
        output += color.bold(".\n")

    # Print the slot statuses.
    slot_statuses = "\nSlot statuses: "
    for i in range(meta.cnt):
        this_slot = get_colored_slot_state_short(meta.slotstate_at_index(i))

        if focus_slot is not None and i == focus_slot:
            this_slot = "[" + this_slot + "]"

        slot_statuses += this_slot

    slot_statuses = color.bold(slot_statuses + "\n")
    # Explain the notation.
    slot_statuses += (
        f"  ({color.bold(get_colored_slot_state_short(mallocng.SlotState.ALLOCATED))}: Inuse (allocated)"
        f" / {color.bold(get_colored_slot_state_short(mallocng.SlotState.FREED))}: Freed"
        f" / {color.bold(get_colored_slot_state_short(mallocng.SlotState.AVAIL))}: Available)\n"
    )

    output += slot_statuses

    return output


def dump_grouped_slot(gslot: mallocng.GroupedSlot, all: bool) -> str:
    output = ""

    if not all:
        output += from_properties(
            "slab",
            [
                Property(name="group", value=gslot.group.addr, is_addr=True),
                Property(name="meta", value=gslot.meta.addr, is_addr=True),
            ],
        )

    output += from_properties(
        "slot",
        [
            Property(name="start", value=gslot.start, is_addr=True),
            Property(name="end", value=gslot.end, is_addr=True),
            Property(name="index", value=gslot.idx),
            Property(name="stride", value=gslot.stride),
            Property(name="state", value=get_colored_slot_state(gslot.slot_state)),
        ],
    )

    if all:
        output += dump_group(gslot.group)
        output += dump_meta(gslot.meta, gslot.idx)

    return output


def dump_slot(
    slot: mallocng.Slot, all: bool, successful_preload: bool, will_dump_gslot: bool
) -> str:
    if successful_preload:
        assert not will_dump_gslot and "Why?"

    all = all and successful_preload and not will_dump_gslot
    output = ""

    if not all:
        if successful_preload:
            output += from_properties(
                "slab",
                [
                    Property(name="group", value=slot.group.addr, is_addr=True),
                    Property(name="meta", value=slot.meta.addr, is_addr=True),
                ],
            )
        else:
            output += from_properties(
                "slab",
                [
                    Property(name="group", value=slot.group.addr, is_addr=True),
                ],
            )

    if successful_preload:
        output += from_properties(
            "general",
            [
                Property(name="start", value=slot.start, is_addr=True),
                Property(name="user start", value=slot.p, is_addr=True, extra="aka `p`"),
                Property(name="end", value=slot.end, is_addr=True, extra="start + stride - 4"),
                Property(
                    name="stride", value=slot.meta.stride, extra="distance between adjacent slots"
                ),
                Property(name="user size", value=slot.user_size, extra='aka "nominal size", `n`'),
                Property(
                    name="slack",
                    value=slot.slack,
                    extra="slot's unused memory / 0x10",
                    alt_value=(slot.slack * mallocng.UNIT),
                ),
                Property(
                    name="state",
                    value=get_colored_slot_state(slot.meta.slotstate_at_index(slot.idx)),
                ),
            ],
        )

    reserved_extra = ["describes: end - p - n"]
    if slot.reserved_in_header == 5:
        reserved_extra.append("use ftr reserved")
    elif slot.reserved_in_header == 6:
        reserved_extra.append("a nested group is in this slot")
    elif slot.reserved_in_header == 7:
        reserved_extra.append("free slot?")

    inband_group = [
        Property(
            name="offset",
            value=slot.offset,
            extra="distance to first slot start / 0x10",
            alt_value=(slot.offset * mallocng.UNIT),
        ),
        Property(name="index", value=slot.idx, extra="index of slot in its group"),
        Property(name="hdr reserved", value=slot.reserved_in_header, extra=reserved_extra),
    ]

    if slot.reserved_in_header == 5:
        ftrsv = "NA (meta error)"
        if successful_preload:
            ftrsv = slot.reserved_in_footer

        inband_group.append(Property(name="ftr reserved", value=ftrsv))

    if successful_preload:
        # Start header fields.
        if slot.is_cyclic():
            cyc_val = slot.cyclic_offset
            cyc_val_alt = cyc_val * mallocng.UNIT
        else:
            cyc_val = "NA"
            cyc_val_alt = "not cyclic"
        inband_group.append(
            Property(
                name="cyclic offset",
                value=cyc_val,
                extra="prevents double free, (p - start) / 0x10",
                alt_value=cyc_val_alt,
            ),
        )
    # We haven't printed the slot state yet. Will we do it with a grouped slot?
    elif not will_dump_gslot:
        # Nope, then let's go ahead and guess.
        inband_group.append(
            Property(
                name="state",
                value=get_colored_slot_state(slot.slot_state),
                extra="(probably, check the meta)",
            )
        )

    output += from_properties("in-band", inband_group)

    if all:
        output += "\n"
        output += dump_group(slot.group)
        output += dump_meta(slot.meta, slot.idx)

    return output


def smart_dump_slot(
    slot: mallocng.Slot, all: bool, gslot: mallocng.GroupedSlot | None = None
) -> str:
    try:
        slot.preload()
    except pwndbg.dbg_mod.Error as e:
        return message.error(f"Error while reading slot: {e}")

    successful_preload: bool = True
    err_msg = ""

    try:
        slot.group.preload()
    except pwndbg.dbg_mod.Error as e:
        err_msg = message.error(f"Error while reading group: {e}")
        successful_preload = False

    if successful_preload:
        try:
            slot.meta.preload()
            try:
                slot.preload_meta_dependants()
            except pwndbg.dbg_mod.Error as e1:
                err_msg = message.error(
                    f"Error while loading slot fields that depend on the meta:\n{e1}"
                )
                successful_preload = False

        except pwndbg.dbg_mod.Error as e2:
            err_msg = message.error(f"Error while reading meta: {e2}")
            successful_preload = False

    if successful_preload:
        # If we successfully got the group and meta, using the grouped_slot won't
        # give us any new information.
        # (Unless the grouped_slot reports a different group than slot.group, which
        # could be possible in exploitation I suppose).
        return dump_slot(slot, all, True, False)

    output = ""

    if not (slot._pn3 == 0xFF or slot._offset == 0):
        # If the group/meta read failed because the slot is freed/avail,
        # we won't throw an error. This is just a heuristic check for
        # better UX. I'm using the private fields for the check so we
        # don't accidentally cause an exception here if we are bordering
        # unreadable memory.
        output += err_msg + "\n"

    if gslot is None:
        if not search_on_fail:
            output += "Could not load valid meta from local information.\n"
            output += "Will not attempt to search the heap because ng-search-on-fail = False.\n\n"
            output += dump_slot(slot, all, False, False)
            return output

        # If it wasn't provided to us, let's try to search for it now.
        output += "Could not load valid meta from local information, searching the heap.. "

        if not ng.init_if_needed():
            output += message.error("\nCouldn't find the allocator, aborting the search. ")
            gslot, fslot = None, None
        else:
            gslot, fslot = ng.find_slot(slot.p, False, False)

        if gslot is None or fslot is None:
            output += "Not found.\n\n"
            output += dump_slot(slot, all, False, False)
            return output
        if fslot.p == slot.p:
            output += "Found it.\n\n"
        else:
            output += "\nFound a slot with p @ " + mem_color.get(fslot.p) + "."
            output += " The slot you are looking for\ndoesn't seem to exist. Maybe its group got freed?\n\n"
            output += "Local memory:\n"
            output += dump_slot(slot, all, False, False)
            return output

    # Now we have a valid gslot.

    output += "Local slot memory:\n"
    output += dump_slot(slot, all, False, True)
    output += "\nSlot information from the group/meta:\n"
    output += dump_grouped_slot(gslot, all)

    return output


def dump_meta_area(meta_area: mallocng.MetaArea, coming_from_dump: bool = False) -> str:
    if coming_from_dump:
        # We don't want users to wonder which colorings in ng-dump are according to
        # state (allocated/avail/freed), and which are according to the memory mapping's color,
        # so we will just disable address coloring here.
        area_range = "@ " + hex(meta_area.addr) + " - " + hex(meta_area.addr + meta_area.area_size)
    else:
        area_range = (
            "@ "
            + mem_color.get(meta_area.addr)
            + " - "
            + mem_color.get(meta_area.addr + meta_area.area_size)
        )

    if coming_from_dump:
        slots = ""
        slots_is_addr = False
        # Don't color according to mapping.
        next_prop = Property(name="next", value=hex(meta_area.next), value_color_func=color.normal)
    else:
        slots = meta_area.slots
        slots_is_addr = True
        next_prop = Property(name="next", value=meta_area.next, is_addr=True)

    output = from_properties(
        "meta_area",
        [
            Property(name="check", value=meta_area.check),
            next_prop,
            Property(name="nslots", value=meta_area.nslots),
            Property(name="slots", value=slots, is_addr=slots_is_addr, extra="array of metas"),
        ],
        preamble=area_range,
    )

    return output


def dump_malloc_context(ctx: mallocng.MallocContext) -> str:
    props = [
        Property(name="secret", value=ctx.secret),
    ]
    if ctx.has_pagesize_field:
        props.append(
            Property(name="pagesize", value=ctx.pagesize),
        )

    props.extend(
        [
            Property(name="init_done", value=ctx.init_done),
            Property(name="mmap_counter", value=ctx.mmap_counter),
            Property(name="free_meta_head", value=ctx.free_meta_head, is_addr=True),
            Property(name="avail_meta", value=ctx.avail_meta, is_addr=True),
            Property(name="avail_meta_count", value=ctx.avail_meta_count),
            Property(name="avail_meta_area_count", value=ctx.avail_meta_area_count),
            Property(name="meta_alloc_shift", value=ctx.meta_alloc_shift),
            Property(name="meta_area_head", value=ctx.meta_area_head, is_addr=True),
            Property(name="meta_area_tail", value=ctx.meta_area_tail, is_addr=True),
            Property(name="avail_meta_areas", value=ctx.avail_meta_areas, is_addr=True),
        ]
    )

    for i in range(len(ctx.active)):
        if ctx.active[i] != 0:
            props.append(Property(name=f"active[{i}]", value=ctx.active[i], is_addr=True))

    for i in range(len(ctx.usage_by_class)):
        if ctx.usage_by_class[i] != 0:
            props.append(Property(name=f"usage_by_class[{i}]", value=ctx.usage_by_class[i]))

    for i in range(len(ctx.unmap_seq)):
        if ctx.unmap_seq[i] != 0:
            props.append(Property(name=f"unmap_seq[{i}]", value=ctx.unmap_seq[i]))

    for i in range(len(ctx.bounces)):
        if ctx.bounces[i] != 0:
            props.append(Property(name=f"bounces[{i}]", value=ctx.bounces[i]))

    props.extend(
        [
            Property(name="seq", value=ctx.seq),
            Property(name="brk", value=ctx.brk, is_addr=True),
        ]
    )

    ctx_addr = "@ " + mem_color.get(ctx.addr)
    output = from_properties("ctx", props, preamble=ctx_addr, value_offset=22)

    return output


def mallocng_slot_user(address: int, all: bool) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {address:#x} not readable."))
        return

    slot = mallocng.Slot(address)
    print(smart_dump_slot(slot, all, None), end="")


def mallocng_slot_start(address: int, all: bool) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {address:#x} not readable."))
        return

    slot = mallocng.Slot.from_start(address)
    print(smart_dump_slot(slot, all, None), end="")


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


def mallocng_group(address: int, index: int | None = None) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {address:#x} not readable."))
        return

    group = mallocng.Group(address)

    try:
        group.preload()
    except pwndbg.dbg_mod.Error as e:
        print(message.error(str(e)))
        return

    if index is None:
        print(dump_group(group), end="")
    else:
        if index < 0:
            print(message.error("Index is negative."))
            return
        print(f"Start of slot {index} is @ " + mem_color.get(group.at_index(index)))

    try:
        meta = group.meta
        meta.preload()

        if index is None:
            print(dump_meta(meta), end="")
        elif index >= meta.cnt:
            # If the index is outside of the group, warn the user.
            print(
                message.warn("Index is outside of group! ") + f"Group hosts only {meta.cnt} slots."
            )

    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Failed loading meta: {e}"))
        print("Cannot determine whether index is within group bounds.")
        return


def mallocng_meta_area(address: int, index: int | None = None) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {address:#x} not readable."))
        return

    try:
        meta_area = mallocng.MetaArea(address)

        print(dump_meta_area(meta_area), end="")

        if index is not None:
            if index < 0:
                print(message.error("\nIndex is negative."))
                return

            print(f"\nMeta {index} is @ " + mem_color.get(meta_area.at_index(index)))

            if index >= meta_area.nslots:
                print(
                    message.warn("Index is outside of meta area! ")
                    + f"Meta area only hosts {meta_area.nslots} meta's."
                )

    except pwndbg.dbg_mod.Error as e:
        print(message.error(str(e)))
        return


def mallocng_malloc_context(address: int | None = None) -> None:
    if address is None:
        if not ng.init_if_needed():
            print(message.error("Couldn't find the allocator, aborting the command."))
            return

        assert ng.ctx, "Successful init but ctx is not set?"
        ctx = ng.ctx
    else:
        if not memory.is_readable_address(address):
            print(message.error(f"Address {address:#x} not readable."))
            return

        try:
            ctx = mallocng.MallocContext(address)
        except pwndbg.dbg_mod.Error as e:
            print(message.error(str(e)))
            return

    print(dump_malloc_context(ctx), end="")


def mallocng_find(
    address: int, all: bool = False, metadata: bool = False, shallow: bool = False
) -> None:
    if not memory.is_readable_address(address):
        print(message.error(f"Address {hex(address)} not readable."))
        return

    if not ng.init_if_needed():
        print(message.error("Couldn't find the allocator, aborting the command."))
        return

    grouped_slot, slot = ng.find_slot(address, metadata, shallow)

    if slot is None:
        print(message.info("No slot found containing that address."))
        return

    print(smart_dump_slot(slot, all, grouped_slot), end="")


VALID_CHARS = list(map(ord, set(string.printable) - set("\t\r\n\x0c\x0b")))


def bin_ascii(bs: bytearray):
    return "".join(chr(c) if c in VALID_CHARS else "." for c in bs)


vis_cyclic_offset_color = color.YELLOW
vis_offset_color = color.LIGHT_YELLOW
vis_cycled_mark_color = color.PURPLE
vis_pn3_reserved_color = color.LIGHT_CYAN
vis_big_offset_check_color = color.BLACK
vis_ftr_reserved_color = color.GREEN


def colorize_pointer(
    address: int, ptrvalue: int, state: mallocng.SlotState, slot: mallocng.Slot
) -> str:
    ptrsize = pwndbg.aglib.typeinfo.ptrsize
    out = f"{ptrvalue:0{ptrsize * 2}x}"

    if state != mallocng.SlotState.ALLOCATED:
        # Nothing to do.
        return out

    # Are we in user data?
    if slot.p <= address < slot.p + slot.nominal_size:
        # Yes, bold the parts that are.
        boldable_bytes = min(slot.p + slot.nominal_size - address, ptrsize)
        plain_part = out[: (-2 * boldable_bytes)]
        bold_part = color.bold(out[(-2 * boldable_bytes) :])
        out = plain_part + bold_part

    # Are we in the p header of this slot?
    if address == slot.p - ptrsize:
        offset_part = color.colorize(out[:4], vis_offset_color)
        pn3_part = color.colorize(out[4:6], vis_pn3_reserved_color)
        big_offset_part = color.colorize(out[6:8], vis_big_offset_check_color)
        plain_part = out[8:]

        out = offset_part + pn3_part + big_offset_part + plain_part

    # Are we in the footer of this slot?
    if address == slot.start + slot.meta.stride - ptrsize:
        # Highlight ftr reserved if it is used.
        if slot.reserved_in_header == 5:
            plain_part = out[:8]
            ftr_reserved_part = color.colorize(out[8:], vis_ftr_reserved_color)
            out = plain_part + ftr_reserved_part

    return out


def colorize_start_header_line(shline: str, state: mallocng.SlotState, slot: mallocng.Slot) -> str:
    if state != mallocng.SlotState.ALLOCATED:
        # Nothing to do.
        return shline

    splitline = shline.split("0x", maxsplit=3)
    assert len(splitline) == 4
    rightvalplus = splitline[3]

    if slot.start != slot.p:
        # A cycled slot. The offset has completely different meaning
        # than in p header. The hdr_res has kinda~ different meaning.
        offset_part = color.colorize(rightvalplus[:4], vis_cyclic_offset_color)
        sorpn3 = color.colorize(rightvalplus[4:6], vis_cycled_mark_color)
    else:
        offset_part = color.colorize(rightvalplus[:4], vis_offset_color)
        sorpn3 = color.colorize(rightvalplus[4:6], vis_pn3_reserved_color)

    big_offset_part = color.colorize(rightvalplus[6:8], vis_big_offset_check_color)
    plain_part = rightvalplus[8:]

    out = (
        f"{splitline[0]}0x{splitline[1]}0x{splitline[2]}0x"
        + offset_part
        + sorpn3
        + big_offset_part
        + plain_part
    )
    return out


def line_decoration(addr: int, slot_state: mallocng.SlotState, slot: mallocng.Slot) -> str:
    """
    Maybe append extra clarification to a line.

    Currently only appends to p headers.
    """
    if slot_state != mallocng.SlotState.ALLOCATED:
        return ""
    if addr != slot.p - 2 * pwndbg.aglib.typeinfo.ptrsize:
        return ""

    return "   " + color.colorize(
        f"{slot.idx} + ({slot.reserved_in_header} << 5)", vis_pn3_reserved_color
    )


default_vis_count = pwndbg.config.add_param(
    "ng-vis-count",
    10,
    "default count for ng-vis",
    param_class=pwndbg.lib.config.PARAM_UINTEGER,
    scope=pwndbg.lib.config.Scope.heap,
)


def mallocng_visualize_slots(address: int, count: int = int(default_vis_count)):
    ptrsize = pwndbg.aglib.typeinfo.ptrsize

    if ptrsize != 8:
        print(message.error("This command only works on architectures where a pointer is 64 bits."))
        return

    if not memory.is_readable_address(address):
        print(message.error(f"Address {address:#x} not readable."))
        return

    if not ng.init_if_needed():
        print(message.error("Couldn't find the allocator, aborting the command."))
        return

    first_grouped_slot, first_slot = ng.find_slot(address, False, False)

    if first_grouped_slot is None or first_slot is None:
        print(message.info("No slot found containing that address."))
        return

    group: mallocng.Group = first_grouped_slot.group
    meta: mallocng.Meta = first_grouped_slot.meta
    first_idx: int = first_grouped_slot.idx

    print("group @ " + mem_color.get(group.addr))
    print("meta @ " + mem_color.get(meta.addr))

    if first_idx + count >= meta.cnt:
        if count != default_vis_count:
            # If the default was passed, no need to warn the user.
            print(
                message.info(
                    f"Clamping count to {meta.cnt - first_idx} to not go over end of group."
                )
            )

        count = meta.cnt - first_idx

    cyc_offset_part = color.colorize("cyclic offset", vis_cyclic_offset_color)
    cycled_mark_part = color.colorize("cycled mark", vis_cycled_mark_color)
    offset_part = color.colorize("offset", vis_offset_color)
    pn3_part = color.colorize("p[-3] = idx + (hdr reserved << 5)", vis_pn3_reserved_color)
    big_offset_part = color.colorize("big offset mark", vis_big_offset_check_color)
    ftr_reserved_part = color.colorize("ftr reserved", vis_ftr_reserved_color)

    legend = (
        "LEGEND: "
        + cyc_offset_part
        + "; "
        + cycled_mark_part
        + "; "
        + offset_part
        + "; "
        + pn3_part
        + "; "
        + big_offset_part
        + "; "
        + ftr_reserved_part
        + "\n"
    )
    legend += (
        "LEGEND: "
        + color.colorize("allo", state_alloc_color)
        + color.colorize("cated", state_alloc_color_alt)
        + "; "
        + color.colorize("fr", state_freed_color)
        + color.colorize("eed", state_freed_color_alt)
        + "; "
        + color.colorize("avai", state_avail_color)
        + color.colorize("lable", state_avail_color_alt)
        + "\n"
    )
    print(legend)

    out: list[str] = []  # List of lines.
    last_color = "nothing"

    # Add the line before the start of the first slot, to include its start header.
    shline_addr = group.at_index(first_idx) - 2 * ptrsize
    shline_bytes = memory.read(shline_addr, ptrsize * 2)
    leftptr = pwndbg.aglib.arch.unpack(shline_bytes[:ptrsize])
    rightptr = pwndbg.aglib.arch.unpack(shline_bytes[ptrsize:])
    out.append(
        f"{shline_addr:#x}\t0x{leftptr:0{ptrsize * 2}x}\t0x{rightptr:0{ptrsize * 2}x}\t{bin_ascii(shline_bytes)}"
    )

    # Iterate over slots
    for idx in range(first_idx, first_idx + count):
        start_address = group.at_index(idx)
        next_start_address = start_address + meta.stride

        if idx == first_idx:
            slot = first_slot
        else:
            try:
                slot = mallocng.Slot.from_start(start_address)
                slot.preload()
                slot.set_group(group)
                # Probably redundant, but just in case.
                slot.preload_meta_dependants()
            except pwndbg.dbg_mod.Error as e:
                print(
                    message.error(
                        f"Error while reading slot {idx} @ {mem_color.get(start_address)}: {e}"
                    )
                )
                return

        slot_state: mallocng.SlotState = meta.slotstate_at_index(idx)
        cur_slot_color = get_slot_color(slot_state, last_color)

        # Colorize the previous line which contains our start header.
        out[-1] = colorize_start_header_line(out[-1], slot_state, slot) + line_decoration(
            start_address - 2 * ptrsize, slot_state, slot
        )

        # Make the output line by line (advance 0x10 bytes at a time).
        cur_address = start_address
        while cur_address < next_start_address:
            line_bytes = memory.read(cur_address, ptrsize * 2)
            leftptr = pwndbg.aglib.arch.unpack(line_bytes[:ptrsize])
            rightptr = pwndbg.aglib.arch.unpack(line_bytes[ptrsize:])

            line_out = f"{cur_address:#x}"
            line_out += "\t0x" + colorize_pointer(cur_address, leftptr, slot_state, slot)
            line_out += "\t0x" + colorize_pointer(cur_address + ptrsize, rightptr, slot_state, slot)
            line_out += f"\t{bin_ascii(line_bytes)}"

            line_out = color.colorize(line_out, cur_slot_color)
            line_out += line_decoration(cur_address, slot_state, slot)

            out.append(line_out)

            cur_address += 2 * ptrsize

        last_color = cur_slot_color

    print("\n".join(out))


def mallocng_dump(meta_area: int | None = None) -> None:
    if not ng.init_if_needed():
        print(message.error("Couldn't find the allocator, aborting the command."))
        return

    assert ng.ctx, "Successful init but ctx is not set?"
    ctx: mallocng.MallocContext = ng.ctx

    try:
        free_metas = ng.get_free_metas()
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Failed traversing free meta chain. {e}"))
        print(message.error("Meta allocation state may be wrong."))
        free_metas = {}

    meta_padding = " " * 10
    slot_padding = " " * 15

    # Rename variables for clarity.
    specified_meta_area = meta_area
    meta_area = None

    if specified_meta_area is not None:
        ma_addr = specified_meta_area
    else:
        # Iterate over all meta_areas
        ma_addr = ctx.meta_area_head
    while ma_addr != 0:
        try:
            meta_area = mallocng.MetaArea(ma_addr)
        except pwndbg.dbg_mod.Error as e:
            print(message.error(f"Cannot read meta area @ {ma_addr:#x}: {e}"))
            break

        print(dump_meta_area(meta_area, coming_from_dump=True))

        # Iterate over all metas in this meta_area
        for i in range(meta_area.nslots):
            meta_addr = meta_area.at_index(i)

            if meta_addr in free_metas:
                print(
                    meta_padding
                    + color.colorize(
                        f"{meta_addr:#x} [{free_metas[meta_addr][0]}]", state_freed_color
                    )
                )
            elif ng.meta_is_avail(meta_addr):
                print(meta_padding + color.colorize(f"{meta_addr:#x}", state_avail_color))
            else:
                print(meta_padding + color.colorize(f"{meta_addr:#x}", state_alloc_color), end="")

                try:
                    meta = mallocng.Meta(meta_addr)
                    meta.preload()
                    group = mallocng.Group(meta.mem)
                    meta.preload()
                except pwndbg.dbg_mod.Error as e:
                    print(message.error(f"Failed resolving meta / group data ({e}). Skipping.."))
                    continue

                print(f" -> group @ {group.addr:#x} (slot size: {meta.stride:#x})")

                # Iterate over all slots in this group
                idx = 0
                while idx < meta.cnt:
                    slot_addr = group.at_index(idx)
                    sstate = meta.slotstate_at_index(idx)
                    cur_slot_color = get_slot_color(sstate)
                    print(
                        slot_padding
                        + color.colorize(f"{slot_addr:#x}", cur_slot_color)
                        + f" [{idx}]"
                    )
                    idx += 1

                print()

        ma_addr = meta_area.next
        print()

        if specified_meta_area is not None:
            # Exit the loop since we're only printing one meta area.
            break


def mallocng_explain() -> None:
    txt = (
        color.bold("mallocng")
        + ' is a slab allocator. The "unit of allocation" is called a '
        + color.bold("slot")
        + "\n"
    )
    txt += '(the equivalent of glibc\'s "chunk"). Slots are in 0x10 granularity and\n'
    txt += (
        "alignment. The slots are organized into objects called "
        + color.bold('"groups"')
        + " (the \n"
    )
    txt += "slabs). Each group is composed of slots of the same size. If a group is big\n"
    txt += "it is allocated using mmap, otherwise it is allocated as a slot of a larger\n"
    txt += "group.\n\n"

    txt += "Each group has some associated metadata. This metadata is stored in a separate\n"
    txt += (
        "object called "
        + color.bold('"meta"')
        + ". Metas are allocated separately from groups in\n"
    )
    txt += color.bold('"meta areas"') + " to make it harder to reach them during exploitation.\n\n"

    txt += "Here are the definitions of group, meta and meta_area.\n\n"

    txt += color.bold("struct group {\n")
    txt += "  // the metadata of this group\n"
    txt += color.bold("  struct meta *meta;\n")
    txt += "  unsigned char active_idx:5;\n"
    txt += "  char pad[UNIT - sizeof(struct meta *) - 1];\n"
    txt += "  // start of the slots array\n"
    txt += color.bold("  unsigned char storage[];\n")
    txt += color.bold("};\n\n")

    txt += color.bold("struct meta {\n")
    txt += "  // doubly linked list connecting meta's\n"
    txt += color.bold("  struct meta *prev, *next;\n")
    txt += "  // which group is this metadata for\n"
    txt += color.bold("  struct group *mem;\n")
    txt += "  // slot bitmap\n"
    txt += "  //   avail - slots which have not yet been allocated\n"
    txt += "  //   freed - free slots\n"
    txt += color.bold("  volatile int avail_mask, freed_mask;\n")
    txt += "  uintptr_t last_idx:5;\n"
    txt += "  uintptr_t freeable:1;\n"
    txt += "  // describes the size of the slots\n"
    txt += color.bold("  uintptr_t sizeclass:6;\n")
    txt += "  // if this group was mmaped, how many pages did we use?\n"
    txt += "  uintptr_t maplen:8*sizeof(uintptr_t)-12;\n"
    txt += color.bold("};\n\n")

    txt += color.bold("struct meta_area {\n")
    txt += "  uint64_t check;\n"
    txt += "  struct meta_area *next;\n"
    txt += "  int nslots;\n"
    txt += "  // start of the meta array\n"
    txt += color.bold("  struct meta slots[];\n")
    txt += color.bold("};\n\n")

    txt += (
        "Two other important definitions are "
        + color.bold("IB")
        + " and "
        + color.bold("UNIT")
        + ".\n\n"
    )

    txt += "// the aforementioned slot alignment.\n"
    txt += color.bold("#define UNIT 16\n")
    txt += "// the size of the in-band metadata.\n"
    txt += color.bold("#define IB 4\n\n")

    txt += "The allocator state is stored in the global `ctx` variable which is of\n"
    txt += "type `struct malloc_context`. It is accessible through the __malloc_context\n"
    txt += "symbol.\n\n"

    txt += color.bold("struct malloc_context {\n")
    txt += color.bold("  uint64_t secret;\n")
    txt += "#ifndef PAGESIZE\n"
    txt += "  size_t pagesize;\n"
    txt += "#endif\n"
    txt += "  int init_done;\n"
    txt += "  unsigned mmap_counter;\n"
    txt += color.bold("  struct meta *free_meta_head;\n")
    txt += color.bold("  struct meta *avail_meta;\n")
    txt += "  size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;\n"
    txt += color.bold("  struct meta_area *meta_area_head, *meta_area_tail;\n")
    txt += color.bold("  unsigned char *avail_meta_areas;\n")
    txt += '  // the "active" group for each sizeclass\n'
    txt += "  // it will be picked for allocation\n"
    txt += color.bold("  struct meta *active[48];\n")
    txt += "  size_t usage_by_class[48];\n"
    txt += "  uint8_t unmap_seq[32], bounces[32];\n"
    txt += "  uint8_t seq;\n"
    txt += "  uintptr_t brk;\n"
    txt += color.bold("};\n\n")

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
as well. Check the {color.bold("enframe()")} function in the source, it is very
important.

{color.bold("idx")} is the index of the slot within its group. The {color.bold("stride")} of
a group is (generally) determined by the sizeclass as
{color.bold("UNIT * size_classes[meta.sizeclass]")}. {color.bold("start")} is the starting
address of the slot (the slot0, slot1, ... in the above diagram).
The start of a slot with index i is {color.bold("group.storage + i * stride")}.
The "nominal size" is the amount of memory the user requested with
their malloc() call, in the source it is also referred to as {color.bold("n")}.

For every slot in a group, the memory in [start - IB, start) contains
some metadata that we will call the "start header". For this reason,
the {color.bold("end")} of a slot is calculated as {color.bold("start + stride - IB")}. The
{color.bold("slack")} of a slot is calculated as {color.bold("(stride - n - IB) / UNIT")} and
describes the amount of unused memory within a slot.

To prevent double-frees and exploitation attempts, the mallocng
allocator performs "cycling" i.e. the actual start of user data
(the pointer returned by malloc) can be at some offset from the
{color.bold("start")} of the slot. The start of user data is called {color.bold("p")} and it
is also UNIT aligned. We will call the distance between {color.bold("p")} and
{color.bold("start")} the "cyclic offset" ({color.bold("off")} in code). When calculating
the cyclic offset, mallocng ensures {color.bold("off <= slack")}.

If a slot is in fact cycled, then that is stored in the start
header as {color.bold("off = *(uint16_t*)(start-2)")} and {color.bold("start[-3] = 7 << 5")}.
The {color.bold("start[-3]")} field acts as a flag.

For every slot, the memory in [p - IB, p) contains some metadata.
We will call this the "p header". If the slot is not cycled i.e.
{color.bold("start == p")}, then [start - IB, start) will contain the p header
fields and start[-3] >> 5 will *not* be 7.

The value in {color.bold("*(uint16_t*)(p-2)")} is the {color.bold("offset")} from the slot's
{color.bold("start")} to the start of the group (divided by UNIT). The value
in {color.bold("p[-4]")} is either 0 or 1 and describes if a "big offset" should
be used. It is usually zero and gets set to one only in some cases
in aligned_alloc(). If it is 1, the offset is to be calculated as
{color.bold("*(uint32_t *)(p - 8)")}.

{color.bold("p[-3]")} contains multiple pieces of information. If {color.bold("p[-3] == 0xFF")}
the slot is freed. Otherwise, the lower 5 bits of p[-3] describe
the index of the slot in its group: {color.bold("idx = p[-3] & 31")}. The top
3 bits desribed the {color.bold("reserved")} area size. This is the memory
between the end of user memory and {color.bold("end")} i.e. {color.bold("reserved = end - p - n")}.

We will call the value {color.bold("p[-3] >> 5")}, "hdr reserved" for "reserved as
specified in the p header". It can happen however, that the value
{color.bold("reserved = end - p - n")} is large and so doesn't fit in the three
bits in p[-3]. In this case "hdr reserved" will be strictly 5, which
denotes that we need to look at the slot's footer to read the actual
value of {color.bold("reserved")}. As a special case, if {color.bold("p[-3] >> 5 == 6")} that
doesn't describe the reserved size at all, but specifies that there
is a group nested inside this slot. {color.bold("p[-3] >> 5")} should never be 7,
contrary to {color.bold("start[-3] >> 5")}.

The "footer" of a slot is the third and final area of a slot's
memory where metadata is contained. This is the [end - 4, end)
area. It only contains the reserved size as
{color.bold("reserved = *(const uint32_t *)(end-4)")} when {color.bold("p[-3] >> 5 == 5")}.

All of the above is only generally true for allocated slots. Mallocng
ensures {color.bold("p[-3] = 0xFF")} and {color.bold("*(uint16_t *)(p - 2) = 0")} for freed slots,
which makes the start of the slot's group (and thus meta) unreachable.
Only in this case does {color.bold("p[-3] >> 5")} become 7. Available slots,
i.e. those that haven't been allocated nor freed yet (but are ready
for allocation), have almost no guarantees on their data and
metadata contents.
"""

    print(txt)


parser = argparse.ArgumentParser(
    description="Utility for inspecting the mallocng (musl) allocator."
)
subparsers = parser.add_subparsers(dest="command")
subparsers.required = True

explain_parser = subparsers.add_parser(
    "explain",
    description="Gives a quick explanation of musl's mallocng allocator.",
    help="Gives a quick explanation of musl's mallocng allocator.",
)

dump_parser = subparsers.add_parser(
    "dump",
    description=f"""
Dump the mallocng heap.

Since the command may produce lots of output, you may want to pipe it to
less with `| ng-dump | less -R`.

The [index] next to the metas is their index in the doubly linked list
pointed to by ctx.freed_meta_head. The [index] next to the slots is
the slot's index inside of its group (thus, these will always be sequential).

Notice that the pointers in the output of this command aren't colored according
to their mapping's color but rather according to the object's allocation status.
Color legend: {color.colorize("allocated", state_alloc_color)}; """
    f"""{color.colorize("freed", state_freed_color)}; {color.colorize("available", state_avail_color)}.
""",
    help="Dump the mallocng heap.",
)
dump_parser.add_argument(
    "-ma", "--meta-area", type=int, help="Dump only the meta area at the provided address."
)

vis_parser = subparsers.add_parser(
    "vis",
    description="Visualize slots in a group.",
    help="Visualize slots in a group.",
)
vis_parser.add_argument(
    "address",
    type=int,
    help="Address which is inside some slot.",
)
vis_parser.add_argument(
    "count",
    type=int,
    default=default_vis_count,
    nargs="?",  # Optional
    help="The amount of slots to visualize.",
)

find_parser = subparsers.add_parser(
    "find",
    description="""
Find slot which contains the given address.

Returns the `start` of the slot. We say a slot 'contains'
an address if the address is in [start, start + stride).
    """,
    help="Find slot which contains the given address.",
)
find_parser.add_argument(
    "address",
    type=int,
    help="The address to look for.",
)
find_parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    default=False,
    help="Print out all information. Including meta and group data.",
)
find_parser.add_argument(
    "-m",
    "--metadata",
    action="store_true",
    default=False,
    help=(
        "If the given address falls onto some in-band metadata, return the slot which owns that metadata."
        " In other words, the containment check becomes [start - IB, end)."
    ),
)
find_parser.add_argument(
    "-s",
    "--shallow",
    action="store_true",
    default=False,
    help=(
        "Return the biggest slot which contains this address, don't recurse for smaller slots. The group "
        " which owns this slot will not be a nested group."
    ),
)

ctx_parser = subparsers.add_parser(
    "ctx",
    description="Print out the mallocng __malloc_context (ctx) object.",
    help="Print out the mallocng __malloc_context (ctx) object.",
)
ctx_parser.add_argument(
    "address",
    nargs="?",
    type=int,
    help="Use the provided address instead of the one Pwndbg found.",
)

metaarea_parser = subparsers.add_parser(
    "metaarea",
    aliases=["ma"],
    description="Print out a mallocng meta_area object at the given address.",
    help="Print out a mallocng meta_area object at the given address.",
)
metaarea_parser.add_argument(
    "address",
    type=int,
    help="The address of the meta_area object.",
)
metaarea_parser.add_argument(
    "-i",
    "--index",
    type=int,
    default=None,
    help="Print address of meta at given index (0-indexed).",
)

group_parser = subparsers.add_parser(
    "group",
    description="Print out information about a mallocng group at the given address.",
    help="Print out information about a mallocng group at the given address.",
)
group_parser.add_argument(
    "address",
    type=int,
    help="The address of the group object.",
)
group_parser.add_argument(
    "-i",
    "--index",
    type=int,
    default=None,
    help="Print start address of slot at given index (0-indexed).",
)

meta_parser = subparsers.add_parser(
    "meta",
    description="Print out information about a mallocng group given the address of its meta.",
    help="Print out information about a mallocng group given the address of its meta.",
)
meta_parser.add_argument(
    "address",
    type=int,
    help="The address of the meta object.",
)

slots_parser = subparsers.add_parser(
    "slots",
    description="Dump information about a mallocng slot, given its start address.",
    help="Dump information about a mallocng slot, given its start address.",
)
slots_parser.add_argument(
    "address",
    type=int,
    help="The start of the slot (not including IB).",
)
slots_parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    default=False,
    help="Print out all information. Including meta and group data.",
)

slotu_parser = subparsers.add_parser(
    "slotu",
    description="Dump information about a mallocng slot, given its user address.",
    help="Dump information about a mallocng slot, given its user address.",
)
slotu_parser.add_argument(
    "address",
    type=int,
    help="The start of user memory. Referred to as `p` in the source.",
)
slotu_parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    default=False,
    help="Print out all information. Including meta and group data.",
)


@pwndbg.commands.Command(
    parser, command_name="mallocng", aliases=["ng"], category=CommandCategory.ALLOCATORS
)
def mallocng_command(
    command: str,
    meta_area: int | None = None,
    address: int | None = None,
    count: int = int(default_vis_count),
    all: bool = False,
    metadata: bool = False,
    shallow: bool = False,
    index: int | None = None,
) -> None:
    if command == "explain":
        mallocng_explain()
        return

    if not pwndbg.aglib.proc.alive():
        print(message.error("mallocng: The program is not being run."))
        return

    match command:
        case "dump":
            mallocng_dump(meta_area)
        case "vis":
            assert address is not None
            mallocng_visualize_slots(address, count)
        case "find":
            assert address is not None
            mallocng_find(address, all, metadata, shallow)
        case "ctx":
            mallocng_malloc_context(address)
        case "metaarea":
            assert address is not None
            mallocng_meta_area(address, index)
        case "group":
            assert address is not None
            mallocng_group(address, index)
        case "meta":
            assert address is not None
            mallocng_meta(address)
        case "slots":
            assert address is not None
            mallocng_slot_start(address, all)
        case "slotu":
            assert address is not None
            mallocng_slot_user(address, all)
