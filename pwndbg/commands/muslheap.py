from __future__ import annotations

import argparse

import gdb

import pwndbg.color
import pwndbg.commands
from pwndbg.color import green
from pwndbg.color import blue
from pwndbg.color import red
from pwndbg.color import message
from pwndbg.color import purple
from pwndbg.color import white
from pwndbg.commands import CommandCategory
from pwndbg.constants import mallocng
from pwndbg.heap.mallocng import MuslMallocngMemoryAllocator
from pwndbg.heap.mallocng import Printer

mheap = MuslMallocngMemoryAllocator()


def _hex(x: int):
    try:
        return hex(x)
    except Exception:
        # Clear sign bit with UINT64_MASK
        # XXX: Does it work in 32-bit arch?
        return hex(int(x) & pwndbg.gdblib.arch.ptrmask)


def _bin(x: int):
    try:
        return bin(x)
    except Exception:
        return bin(int(x) & pwndbg.gdblib.arch.ptrmask)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Dumps the musl mallocng heap state using malloc_context""",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MUSLHEAP)
# @pwndbg.commands.OnlyWithResolvedHeapSyms
# @pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def mheapinfo() -> None:
    """Dumps the musl mallocng heap state using malloc_context"""
    if not mheap.check_mallocng():
        return
    bold_purple = lambda s: pwndbg.color.purple(s, bold=True)
    bold_white = lambda s: pwndbg.color.white(s, bold=True)
    printer = Printer(header_clr=bold_purple, content_clr=bold_white, header_rjust=16)
    P = printer.print

    # Print out useful fields in __malloc_context
    P("secret", _hex(mheap.ctx["secret"]))
    P("mmap_counter", _hex(mheap.ctx["mmap_counter"]))

    # Print out available meta objects
    P(
        "avail_meta",
        green(_hex(mheap.ctx["avail_meta"]), bold=True)
        + white(" (count: %d)" % mheap.ctx["avail_meta_count"], bold=True),
    )

    # Walk and print out free_meta chain
    m = head = mheap.ctx["free_meta_head"]
    if head:
        s = blue(_hex(head), bold=True)
        try:
            while head != m["next"]:
                m = m["next"]
                s += bold_white(" -> ") + blue(_hex(m), bold=True)
        except gdb.MemoryError:
            # Most recently accessed memory may be invaild
            s += red(" (Invaild memory)", bold=True)
        finally:
            P("free_meta", s)
    else:
        P("free_meta", bold_white("0"))

    # Print out available meta areas
    P(
        "avail_meta_area",
        blue(_hex(mheap.ctx["avail_meta_areas"]), bold=True)
        + bold_white(" (count: %d)" % mheap.ctx["avail_meta_area_count"]),
    )

    # Walk and print out meta_area chain
    ma = mheap.ctx["meta_area_head"]
    if ma:
        s = blue(_hex(ma), bold=True)
        try:
            while ma["next"]:
                ma = ma["next"]
                s += bold_white(" -> ") + blue(_hex(ma), bold=True)
        except gdb.MemoryError:
            # Most recently accessed memory may be invaild
            s += red(" (Invaild memory)", bold=True)
        finally:
            P("meta_area_head", s)
    else:
        P("meta_area_head", bold_white("0"))
    if mheap.ctx["meta_area_tail"]:
        P("meta_area_tail", blue(_hex(mheap.ctx["meta_area_tail"]), bold=True))
    else:
        P("meta_area_tail", bold_white("0"))

    # Walk active bin
    bold_green = lambda s: pwndbg.color.green(s, bold=True)
    printer.set(header_clr=bold_green, content_clr=None)
    for i in range(48):
        m = head = mheap.ctx["active"][i]
        if head:
            s = blue(_hex(m), bold=True)
            try:
                while True:
                    s += blue(" (mem: ", bold=True) + purple(_hex(m["mem"])) + blue(")", bold=True)
                    if head == m["next"]:
                        break
                    m = m["next"]
                    s += bold_white(" -> ") + blue(_hex(m), bold=True)
            except gdb.MemoryError:
                # Most recently accessed memory may be invaild
                s += red(" (Invaild memory)", bold=True)
            finally:
                stride_tips = " [0x%lx]" % (mheap.size_classes[i] * mallocng.UNIT)
                P("active.[%d]" % i, s + stride_tips)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Display useful variables and functions in musl-libc
    """,
)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Find the musl mallocng slot index of the given address

    Usage: mfindslot <address>
    """,
)

# FIXME: It would be nice to be able to parse expressions like: (Table *)(0x124)->array
parser.add_argument(
    "addr",
    type=int,
    nargs="?",
    default=None,
    help="Slot (aka chunk) address",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MUSLHEAP)
@pwndbg.commands.OnlyWhenUserspace
def mfindslot(addr: int | None = None) -> None:
    """Find the musl mallocng slot index of the given address

    This works by traversing the `ctx.meta_area_head` chain of meta structures and checking if the given address
    is within the associated group.
    """
    if not mheap.check_mallocng():
        return

    if addr is None:
        print(message.error("Please provide a slot (aka chunk) address"))
        return
    gdbval = gdb.Value(addr)
    p = gdbval.cast(gdb.lookup_type("uint8_t").pointer())

    # Find slots by traversing `ctx.meta_area_head` chain
    result = mheap.search_chain(p)
    if len(result) == 0:
        print(
            message.warn(
                "Not found. This address may not be managed by mallocng or the slot meta is corrupted."
            )
        )
        return
    elif len(result) == 1:
        meta, index = result[0]
    else:
        # Multiple slots owning `p` is found.
        # It's normal because mallocng may internally use a large slot to hold group with smaller slots.
        # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n260)

        # Find slot which is actually managing `p` (the one with the smallest stride).
        meta, index = result[0]
        for x in result:
            if x[0]["sizeclass"] < meta["sizeclass"]:
                meta, index = x

    print(
        green("Found:", bold=True),
        "slot index is %s, owned by meta object at %s."
        % (blue(index, bold=True), purple(_hex(meta))),
    )

    # Display slot and (out-of-band) meta information about the slot
    try:
        mheap.display_meta(meta, index=index)
        if meta == 0:
            return
        mheap.display_ob_slot(p, meta, index)
    except gdb.error as e:
        print(message.error("ERROR: " + str(e)))
        return


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Display the musl mallocng slot (aka chunk) details

    Usage: mslotinfo <addr>
      * addr - A memory address that can be freed by `free()`, usually the one returned from `malloc()`.
            In general, it should be a pointer to the `user_data` field of an *in-use* slot.
            (Use `mfindslot` command to explore a memory address at arbitrary offset of a slot)
    """,
)

# FIXME: It would be nice to be able to parse expressions like: (Table *)(0x124)->array

parser.add_argument(
    "addr",
    type=int,
    nargs="?",
    default=None,
    help="Slot (aka chunk) address",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MUSLHEAP)
@pwndbg.commands.OnlyWhenUserspace
def mslotinfo(addr: int | None = None) -> None:
    """Display the musl mallocng slot (aka chunk) details"""

    if not mheap.check_mallocng():
        return

    if addr is None:
        print(message.error("Please provide a slot (aka chunk) address"))
        return

    gdbval = gdb.Value(addr)
    p = gdbval.cast(gdb.lookup_type("uint8_t").pointer())

    # Parse in-band meta
    try:
        ib = mheap.parse_ib_meta(p)
    except gdb.error as e:
        print(message.error("ERROR:"), str(e))
        return

    # Display in-band meta information
    mheap.display_ib_meta(p, ib)

    # Get group struct object
    if not ib["overflow_in_band"]:
        offset = ib["offset16"]
    else:
        offset = ib["offset32"]
    addr = p - (offset + 1) * mallocng.UNIT
    group_type = mheap.get_group_type()
    if not group_type:
        print(message.error("Failed to get mallocng group type"))
        return
    group = pwndbg.gdblib.memory.get_typed_pointer_value(group_type, addr)
    if not group:
        print(message.error("ERROR:"), "Failed to get group object")
        return

    # Display group and (out-band) meta information
    try:
        mheap.display_group(group)
        meta = group["meta"]
        if not meta:
            print(message.error("Failed to find meta object"))
            return
        mheap.display_meta(meta, ib=ib)
    except gdb.error as e:
        print(message.error("ERROR:"), str(e))
        return

    # Check if we have vaild stride / sizeclass
    stride = mheap.get_stride(group["meta"])
    if stride:
        # Display the result of nontrivial_free()
        mheap.display_nontrivial_free(ib, group)

        # Display slot information
        try:
            mheap.display_ib_slot(p, group["meta"], ib)
        except gdb.error as e:
            print(message.error("ERROR:"), str(e))
            return
    else:
        print(
            message.error(
                "\nCan't get slot and nontrivial_free() information due to invaild sizeclass"
            )
        )
