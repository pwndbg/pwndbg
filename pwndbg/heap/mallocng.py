from __future__ import annotations

import re
from pathlib import Path
from typing import Dict
from typing import List
from typing import Tuple

import gdb

import pwndbg.gdblib.symbol
from pwndbg.color import blue
from pwndbg.color import cyan
from pwndbg.color import green
from pwndbg.color import purple
from pwndbg.color import red
from pwndbg.color import white
from pwndbg.color import yellow
from pwndbg.color import message
from pwndbg.constants import mallocng


# FIXME: Find some pwndbg replacement?
class Printer:
    """A helper class for pretty printing"""

    def __init__(
        self,
        header_rjust: int | None = None,
        header_ljust: int | None = None,
        header_clr: int | None = None,
        content_clr: int | None = None,
    ) -> None:
        self.HEADER_RJUST = header_rjust
        self.HEADER_LJUST = header_ljust
        self.HEADER_CLR = header_clr
        self.CONTENT_CLR = content_clr

    def set(
        self,
        header_rjust: int | None = None,
        header_ljust: int | None = None,
        header_clr: int | None = None,
        content_clr: int | None = None,
    ) -> None:
        """Set Printer config for coloring and aligning"""

        if header_rjust:
            self.HEADER_RJUST = header_rjust
        if header_ljust:
            self.HEADER_LJUST = header_ljust
        if header_clr:
            self.HEADER_CLR = header_clr
        if content_clr:
            self.CONTENT_CLR = content_clr

    def print(self, header: str, content: str, warning: str = "") -> None:
        """Print out message with coloring and aligning"""

        header, content, warning = map(str, (header, content, warning))

        # Aligning (header)
        if self.HEADER_RJUST:
            header = header.rjust(self.HEADER_RJUST)
        elif self.HEADER_LJUST:
            header = header.ljust(self.HEADER_LJUST)
        header += " :"

        # Coloring (header)
        if self.HEADER_CLR:
            header = self.HEADER_CLR(header)
        # Coloring (warning)
        if warning:
            warning = yellow("[" + warning + "]", bold=True)
            # Coloring (content)
            # Use red for content coloring if warning message is given
            content = red(content, bold=True)
        elif self.CONTENT_CLR:
            content = self.CONTENT_CLR(content)

        # Build and print out message
        if warning:
            ctx = "%s %s %s" % (header, content, warning)
        else:
            ctx = "%s %s" % (header, content)
        print(ctx)


# FIXME: Is there an existing version of these somewhere already in pwndbg?
def _hex(x: int) -> str:
    try:
        return hex(x)
    except Exception:
        # Clear sign bit with UINT64_MASK
        # XXX: Does it work in 32-bit arch?
        return hex(int(x) & pwndbg.gdblib.arch.ptrmask)


def _bin(x: int) -> str:
    try:
        return bin(x)
    except Exception:
        return bin(int(x) & pwndbg.gdblib.arch.ptrmask)


def generate_mask_str(avail_mask: int, freed_mask: int) -> Tuple[str, str]:
    """Generate pretty-print string for avail_mask and freed_mask

    Example:
       avail_mask : 0x7f80 (0b111111110000000)
       freed_mask : 0x0    (0b000000000000000)
    """

    # Hex strings for avail_mask and freed_mask
    ah = _hex(avail_mask)
    fh = _hex(freed_mask)
    maxlen = max(len(ah), len(fh))
    ah = ah.ljust(maxlen)  # fills ' '
    fh = fh.ljust(maxlen)

    # Binary strings for avail_mask and freed_mask
    ab = _bin(avail_mask).replace("0b", "")
    fb = _bin(freed_mask).replace("0b", "")
    maxlen = max(len(ab), len(fb))
    ab = ab.zfill(maxlen)  # fills '0'
    fb = fb.zfill(maxlen)

    avail_str = ah + white(" (0b%s)" % ab, bold=True)
    freed_str = fh + white(" (0b%s)" % fb, bold=True)
    return (avail_str, freed_str)


def generate_slot_map(meta: Dict, mask_index: int | None = None) -> str:
    """Generate a map-like string to display the status of all slots in a group.

    If mask_index is set, mask the specified slot in status map.

    Example:
       Slot status map: UUUAAAAFFUUUUUUU[U]UUUUUUUUUUUUU (from slot 29 to slot 0)
        (U: Inuse / A: Available / F: Freed)
    """

    legend = " (%s: Inuse / %s: Available / %s: Freed)" % (
        white("U", bold=True),
        green("A", bold=True),
        red("F", bold=True),
    )

    avail_mask = meta["avail_mask"]
    freed_mask = meta["freed_mask"]
    slot_count = int(meta["last_idx"]) + 1

    # Generate slot status map
    mapstr = ""
    for idx in range(slot_count):
        avail = avail_mask & 1
        freed = freed_mask & 1
        if not freed and not avail:
            # Inuse
            s = white("U", bold=True)
        elif not freed and avail:
            # Available
            s = green("A", bold=True)
        elif freed and not avail:
            # Freed
            s = red("F", bold=True)
        else:
            s = "?"
        # Mask the slot with index `mask_index` in the map
        if idx == mask_index:
            s = "[" + s + "]"
        mapstr = s + mapstr

        avail_mask >>= 1
        freed_mask >>= 1

    if slot_count > 1:
        mapstr += " (from slot %s to slot %s)" % (
            blue(slot_count - 1, bold=True),
            blue("0", bold=True),
        )

    output = purple("\nSlot status map: ", bold=True) + mapstr + "\n" + legend
    return output


class MuslMallocngMemoryAllocator(pwndbg.heap.heap.MemoryAllocator):
    # FIXME: Add a lint bypass to make this stay more readable?
    size_classes = [
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        12,
        15,
        18,
        20,
        25,
        31,
        36,
        42,
        50,
        63,
        72,
        84,
        102,
        127,
        146,
        170,
        204,
        255,
        292,
        340,
        409,
        511,
        584,
        682,
        818,
        1023,
        1169,
        1364,
        1637,
        2047,
        2340,
        2730,
        3276,
        4095,
        4680,
        5460,
        6552,
        8191,
    ]

    def __init__(self) -> None:
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n40
        # `ctx` (or `__malloc_context`) contains mallocng internal status (such as `active` and `free_meta_head`)
        self.ctx = None

    # FIXME: Add heuristic check similar to bata gef
    def check_mallocng(
        self,
    ) -> bool:
        """Check if mallocng is availble on current environment

        It simply checks if `__malloc_context` symbol is existed. If so, set the symbol value found as `self.ctx`.
        """

        sv = pwndbg.gdblib.symbol.value("__malloc_context")
        if sv is None:
            err_msg = """\
    ERROR: can't find musl-libc debug symbols!

    muslheap.py requires musl-libc 1.2.1+ with debug symbols installed.

    Either debug symbols are not installed or broken, or a libc without mallocng support (e.g. musl-libc < 1.2.1 or glibc) is used."""
            print(message.error(err_msg))
            return False
        else:
            self.ctx = sv
        return True

    # FIXME: This should be a generic musl-related function elsewhere in pwndbg
    def get_libcbase(self) -> int | None:
        """Find and get musl libc.so base address from current memory mappings"""

        # FIXME: check for any other alternative names for the musl-libc library?
        soname_pattern = [
            r"^ld-musl-.+\.so\.1$",
            r"^libc\.so$",
            r"^libc\.musl-.+\.so\.1$",
        ]

        for mapping in pwndbg.gdblib.vmmap.get():
            objfile = mapping.objfile
            if not objfile or objfile.startswith("["):
                continue
            objfn = Path(objfile).name
            for pattern in soname_pattern:
                if re.match(pattern, objfn):
                    return mapping.vaddr

        print(message.warn("Warning: can't find musl-libc in memory mappings!\n"))

        return None

    def get_group_type(self) -> gdb.Value | None:
        """Find the struct group indirectly using the meta group

        There is another common `struct group` in grp.h that complicates pulling out the musl mallocng `struct group`,
        because gdb will favour the first one it finds. And I'm also not sure that we want to rely on a specific context
        block to pass to lookup_type. So since we know meta use is what we want, we just pull it from there.

        FIXME: This could probably be abstracted to be a helper in pwndbg.gdblib.typeinfo
        """

        meta_type = gdb.lookup_type("struct meta")
        if meta_type is None:
            print(message.error("Type 'struct meta' not found."))
            return None
        # Purposely fuzzy find the member in case meta ever changes
        group_type = None
        for field in meta_type.fields():
            if str(field.type).startswith("struct group *"):
                group_type = field.type.target()
                break
        if group_type is None:
            print(message.error("Type 'struct group' not found in the 'meta' structure."))
            return None
        return group_type

    def get_stride(self, g: Dict) -> int | None:
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n175

        last_idx = int(g["last_idx"])
        maplen = int(g["maplen"])
        sizeclass = int(g["sizeclass"])

        if not last_idx and maplen:
            return maplen * 4096 - mallocng.UNIT
        elif sizeclass < 48:
            return self.size_classes[sizeclass] * mallocng.UNIT
        else:
            # Return None if we failed to get stride
            return None

    def is_bouncing(self, sc: int) -> bool:
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n283

        return (sc - 7 < 32) and int(self.ctx["bounces"][sc - 7]) >= 100

    def okay_to_free(self, g: Dict) -> bool:
        # http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/free.c?h=v1.2.2#n38

        if not g["freeable"]:
            return False

        sc = int(g["sizeclass"])
        cnt = int(g["last_idx"]) + 1
        usage = int(self.ctx["usage_by_class"][sc])
        stride = self.get_stride(g)

        if (
            sc >= 48
            or stride < mallocng.UNIT * self.size_classes[sc]
            or (not g["maplen"])
            or g["next"] != g
            or (not self.is_bouncing(sc))
            or (9 * cnt <= usage and cnt < 20)
        ):
            return True

        return False

    def search_chain(self, p: gdb.Value) -> List:
        """Find slots where `p` is inside by traversing `ctx.meta_area_head` chain"""

        p = int(p)

        result = []
        try:
            # Traverse every meta object in `meta_area_head` chain
            meta_area = self.ctx["meta_area_head"]
            while meta_area:
                for i in range(int(meta_area["nslots"])):
                    meta = meta_area["slots"][i]
                    if not meta["mem"]:
                        # Skip unused
                        continue
                    stride = self.get_stride(meta)
                    if not stride:
                        # Skip invaild stride
                        continue
                    storage = int(meta["mem"]["storage"].address)
                    slot_count = int(meta["last_idx"]) + 1
                    group_start = int(meta["mem"])
                    group_end = storage + slot_count * stride - mallocng.IB
                    # Check if `p` is in the range of the group owned by this meta object
                    if p >= group_start and p < group_end:
                        if p >= (storage - mallocng.IB):
                            # Calculate the index of the slot where `p` is inside
                            slot_index = (p - (storage - mallocng.IB)) // stride
                        else:
                            # `p` is above the first slot, which means it's not inside of any slots in this group
                            # However, we set the slot index to 0 (the first slot). It's acceptable in most cases.
                            slot_index = 0
                        # We need a pointer (struct meta*), not the object itself
                        m = pwndbg.gdblib.memory.get_typed_pointer("struct meta", meta.address)
                        if not m:
                            print(
                                red("ERROR:", bold=True), "Failed to get the pointer of struct meta"
                            )
                            return result
                        result.append((m, slot_index))
                meta_area = meta_area["next"]
        except gdb.MemoryError as e:
            print(red("ERROR:", bold=True), str(e))

        return result

    # Called by mfindslot
    def display_ob_slot(self, p: gdb.Value, meta: Dict, index: int) -> None:
        """Display slot out-of-band information

        This allows you to find information about uninitialized slots.
        """

        print(white("\n=========== SLOT OUT-OF-BAND ============= ", bold=True))
        bold_purple = lambda s: purple(s, bold=True)
        bold_blue = lambda s: blue(s, bold=True)
        printer = Printer(header_clr=bold_purple, content_clr=bold_blue, header_rjust=10)
        P = printer.print

        stride = self.get_stride(meta)
        slot_start = meta["mem"]["storage"][stride * index].address

        # Display the offset from slot to `p`
        offset = int(p - slot_start)
        if offset == 0:
            offset_tips = white("0", bold=True)
        elif offset > 0:
            offset_tips = green("+" + hex(offset), bold=True)
        else:
            offset_tips = red(hex(offset), bold=True)
        offset_tips = " (offset: %s)" % offset_tips

        P("address", blue(_hex(slot_start), bold=True) + offset_tips)
        P("index", index)
        P("stride", hex(stride))
        P("meta obj", purple(_hex(meta)))

        # Check slot status
        #
        # In mallocng, a slot can be in one of the following status:
        #  INUSE - slot is in use by user
        #  AVAIL - slot is can be allocated to user
        #  FREED - slot is freed
        #
        freed = (meta["freed_mask"] >> index) & 1
        avail = (meta["avail_mask"] >> index) & 1
        if not freed and not avail:
            # Calculate the offset to `user_data` field
            reserved_in_slot_head = (
                pwndbg.gdblib.memory.get_typed_pointer_value("uint8_t", slot_start - 3) & 0xE0
            ) >> 5
            if reserved_in_slot_head == 7:
                cycling_offset = pwndbg.gdblib.memory.get_typed_pointer_value(
                    "uint16_t", slot_start - 2
                )
                ud_offset = cycling_offset * mallocng.UNIT
            else:
                ud_offset = 0

            userdata_ptr = slot_start + ud_offset
            P(
                "status",
                "%s (userdata --> %s)"
                % (white("INUSE", bold=True), blue(_hex(userdata_ptr), bold=True)),
            )
            print("(HINT: use `mslotinfo %s` to display in-band details)" % _hex(userdata_ptr))
        elif not freed and avail:
            P("status", green("AVAIL", bold=True))
        elif freed and not avail:
            P("status", red("FREED", bold=True))
        else:
            P("status", white("?", bold=True))

    def parse_ib_meta(self, p: gdb.Value) -> Dict:
        """Parse 4-byte in-band meta and offset32"""

        ib = {
            "offset16": pwndbg.gdblib.memory.get_typed_pointer_value("uint16_t", p - 2),
            "index": pwndbg.gdblib.memory.get_typed_pointer_value("uint8_t", p - 3) & 0x1F,
            "reserved_in_band": (
                pwndbg.gdblib.memory.get_typed_pointer_value("uint8_t", p - 3) & 0xE0
            )
            >> 5,
            "overflow_in_band": pwndbg.gdblib.memory.get_typed_pointer_value("uint8_t", p - 4),
            "offset32": pwndbg.gdblib.memory.get_typed_pointer_value("uint32_t", p - 8),
        }
        return ib

    def display_ib_meta(self, p: gdb.Value, ib: Dict) -> None:
        """Display in-band meta"""

        print(white("============== IN-BAND META ==============", bold=True))
        bold_green = lambda s: green(s, bold=True)
        bold_blue = lambda s: blue(s, bold=True)
        printer = Printer(header_clr=bold_green, content_clr=bold_blue, header_rjust=13)
        P = printer.print

        # IB: Check index
        index = ib["index"]
        if index < 0x1F:
            P("INDEX", index)
        else:
            P("INDEX", _hex(index), "EXPECT: index < 0x1f")

        # IB: Check reserved_in_band
        reserved_in_band = ib["reserved_in_band"]
        if reserved_in_band < 5:
            P("RESERVED", reserved_in_band)
        elif reserved_in_band == 5:
            P("RESERVED", "5" + purple(" (Use reserved in slot end)", bold=True))
        elif reserved_in_band == 6:
            # This slot may be used as a group in mallocng internal.
            # It can't be freed by free() since `reserved_in_band` is illegal.
            # (See https://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c?h=v1.2.2#n269)
            P(
                "RESERVED",
                "%s %s %s"
                % (
                    red("6", bold=True),
                    yellow("[EXPECT: <= 5]", bold=True),
                    purple("(This slot may internally used as a group)", bold=True),
                ),
            )
        else:
            P("RESERVED", _hex(reserved_in_band), "EXPECT: <= 5")

        # IB: Check overflow
        offset16 = ib["offset16"]
        overflow_in_band = ib["overflow_in_band"]
        if not overflow_in_band:
            group_ptr = p - (offset16 + 1) * mallocng.UNIT
            P("OVERFLOW", 0)
            P("OFFSET_16", "%s (group --> %s)" % (_hex(offset16), _hex(group_ptr)))
        else:
            # `offset32` can be used as the offset to group object
            # instead of `offset16` in IB if `overflow_in_band` is not NULL.
            # It is unlikely to happen in musl-libc for this feature
            # is only used in aligned_alloc() and comes with restriction:
            #   offset32  > 0xffff and offset16 == 0
            offset32 = ib["offset32"]
            group_ptr = p - (offset32 + 1) * mallocng.UNIT
            P(
                "OVERFLOW",
                white(_hex(overflow_in_band), bold=True)
                + purple(" (Use 32-bit offset)", bold=True),
            )
            if offset32 > 0xFFFF:
                P("OFFSET_32", "%s (group --> %s)" % (_hex(offset32), _hex(group_ptr)))
            else:
                P("OFFSET_32", _hex(offset32), "EXPECT: > 0xffff")
            if offset16:
                P(
                    "OFFSET_16",
                    _hex(offset16),
                    "EXPECT: *(uint16_t*)(%s) == 0]" % _hex(p - 2),
                )

    def display_group(self, group: Dict) -> None:
        """Display group information"""

        print(
            white("\n================= GROUP ================== ", bold=True)
            + "(at %s)" % _hex(group.address)
        )
        bold_cyan = lambda s: cyan(s, bold=True)
        bold_blue = lambda s: blue(s, bold=True)
        printer = Printer(header_clr=bold_cyan, content_clr=bold_blue, header_rjust=13)
        P = printer.print

        meta = group["meta"]
        P("meta", _hex(meta))
        P("active_idx", int(group["active_idx"]))
        if meta == 0:
            print(message.warn("WARNING: group.meta is NULL. Likely unintialized IB data."))

    # NOTE: Check was added to deduplicate both display_meta() functions from
    # muslheap, as they were mostly similar.
    def display_meta(self, meta: Dict, ib: Dict | None = None, index: int | None = None):
        """Display meta information

        This gets called in two contexts, one where ib is known and one where index
        is known.
        """

        # Careful here to avoid 'not index' test, as it can legitimately be 0
        if not ib and index is None:
            raise ValueError("display_meta() requires either ib or index")
        if meta == 0:
            print(message.warn("WARNING: display_meta() can't parse NULL meta object"))
            return
        group = meta["mem"].dereference()

        if ib:
            index = ib["index"]
            if not ib["overflow_in_band"]:
                offset = ib["offset16"]
            else:
                offset = ib["offset32"]

        print(
            white("\n================== META ================== ", bold=True)
            + "(at %s)" % _hex(meta)
        )
        bold_purple = lambda s: purple(s, bold=True)
        bold_blue = lambda s: blue(s, bold=True)
        printer = Printer(header_clr=bold_purple, content_clr=bold_blue, header_rjust=13)
        P = printer.print

        # META: Check prev, next (no validation)
        P("prev", _hex(meta["prev"]))
        P("next", _hex(meta["next"]))

        # META: Check mem
        mem = meta["mem"]
        if group.address == mem:
            P("mem", _hex(mem))
        else:
            P("mem", _hex(mem), "EXPECT: 0x%lx" % group.address)

        # META: Check last_idx
        last_idx = meta["last_idx"]
        if index <= last_idx:
            P("last_idx", last_idx)
        else:
            P("last_idx", last_idx, "EXPECT: index <= last_idx")

        avail_mask = meta["avail_mask"]
        freed_mask = meta["freed_mask"]
        avail_str, freed_str = generate_mask_str(avail_mask, freed_mask)

        # META: Check avail_mask
        if ib is None or not (avail_mask & (1 << index)):
            P("avail_mask", avail_str)
        else:
            # If we have in-band data, assume we are looking at an in-use chunk,
            # otherwise fetched IB data could be invalid
            P("avail_mask", avail_str, "EXPECT: !(avail_mask & (1<<index))")

        # META: Check freed_mask
        if ib is None or not (freed_mask & (1 << index)):
            P("freed_mask", freed_str)
        else:
            # If we have in-band data, assume we are looking at an in-use chunk,
            # otherwise fetched IB data could be invalid
            P("freed_mask", freed_str, "EXPECT: !(freed_mask & (1<<index))")

        # META: Check area->check
        area = pwndbg.gdblib.memory.get_typed_pointer_value("struct meta_area", int(meta) & -4096)

        secret = self.ctx["secret"]
        if area["check"] == secret:
            P("area->check", _hex(area["check"]))
        else:
            P(
                "area->check",
                _hex(area["check"]),
                "EXPECT: *(0x%lx) == 0x%lx" % (int(meta) & -4096, secret),
            )

        # META: Check sizeclass
        sc = int(meta["sizeclass"])
        # FIXME: Make this a constant
        # 63 is a special sizeclass for single slot group allocations
        if sc == 63:
            stride = self.get_stride(meta)
            if stride:
                P("sizeclass", "63 " + white(" (stride: 0x%lx)" % stride, bold=True))
            else:
                P("sizeclass", "63 " + white(" (stride: ?)", bold=True))
        elif sc < 48:
            sc_stride = mallocng.UNIT * self.size_classes[sc]
            real_stride = self.get_stride(meta)
            if not real_stride:
                stride_tips = white("(stride: 0x%lx, real_stride: ?)" % sc_stride, bold=True)
            elif sc_stride != real_stride:
                stride_tips = white(
                    "(stride: 0x%lx, real_stride: 0x%lx)" % (sc_stride, real_stride), bold=True
                )
            else:
                stride_tips = white("(stride: 0x%lx)" % sc_stride, bold=True)
            bad = 0
            # Validation requires in-band data, which we won't have from mfindslot
            if ib:
                if not (offset >= self.size_classes[sc] * index):
                    P(
                        "sizeclass",
                        "%d %s" % (sc, stride_tips),
                        "EXPECT: offset >= self.size_classes[sizeclass] * index",
                    )
                    bad = 1
                if not (offset < self.size_classes[sc] * (index + 1)):
                    P(
                        "sizeclass",
                        "%d %s" % (sc, stride_tips),
                        "EXPECT: offset < self.size_classes[sizeclass] * (index + 1)",
                    )
                    bad = 1
            if not bad:
                P("sizeclass", "%d %s" % (sc, stride_tips))
        else:
            P("sizeclass", sc, "EXPECT: sizeclass < 48 || sizeclass == 63")

        # META: Check maplen
        maplen = int(meta["maplen"])
        if maplen:
            if offset <= (maplen * (4096 // mallocng.UNIT)) - 1:
                P("maplen", _hex(maplen))
            else:
                P(
                    "maplen",
                    _hex(maplen),
                    "EXPECT: offset <= maplen * %d - 1" % (4096 // mallocng.UNIT),
                )
        else:
            P("maplen", 0)

        # META: Check freeable
        P("freeable", meta["freeable"])

        # META: Check group allocation method
        if not meta["freeable"]:
            # This group is a donated memory.
            # That is, it was placed in an unused RW memory area from a object file loaded by ld.so.
            # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/donate.c?h=v1.2.2#n10)

            group_addr = int(group.address)

            # Find out which object file in memory mappings donated this memory.
            vmmap = pwndbg.gdblib.vmmap.get()
            for mapping in vmmap:
                start = mapping.vaddr
                end = mapping.vaddr + mapping.memsz
                objfile = mapping.objfile
                if not objfile or objfile.startswith("["):
                    continue
                if group_addr > start and group_addr < end:
                    method = "donated from %s" % white(objfile, bold=True)
                    break
            else:
                method = "donated from an unknown object file"
        elif not meta["maplen"]:
            # XXX: Find out which group is used.
            method = white("another group's slot", bold=True)
        else:
            method = white("individual mmap", bold=True)
        print(purple("\nGroup allocation method : ", bold=True) + method)

        # Display slot status map
        print(generate_slot_map(meta, index))

    def display_nontrivial_free(self, ib: Dict, group: Dict) -> None:
        """Display the result of nontrivial_free()"""

        bold_purple = lambda s: purple(s, bold=True)
        bold_green = lambda s: green(s, bold=True)
        printer = Printer(header_clr=bold_purple, content_clr=bold_green)
        P = printer.print
        print()

        print_dq = print_fg = print_fm = 0

        meta = group["meta"]
        sizeclass = int(meta["sizeclass"])
        index = int(ib["index"])

        mask = int(meta["freed_mask"] | meta["avail_mask"])
        slf = (1 << index) & mallocng.UINT32_MASK
        if mask + slf == (2 << meta["last_idx"]) - 1 and self.okay_to_free(meta):
            if meta["next"]:
                if sizeclass < 48:
                    P("Result of nontrivial_free()", "dequeue, free_group, free_meta")
                else:
                    P(
                        "Result of nontrivial_free()",
                        "dequeue, free_group, free_meta",
                        "EXPECT: sizeclass < 48",
                    )
                print_dq = print_fg = print_fm = 1
            else:
                P("Result of nontrivial_free()", "free_group, free_meta")
                print_fg = print_fm = 1
        elif not mask and self.ctx["active"][sizeclass] != meta:
            if sizeclass < 48:
                P("Result of nontrivial_free()", "queue (active[%d])" % sizeclass)
            else:
                P(
                    "Result of nontrivial_free()",
                    "queue (active[%d])" % sizeclass,
                    "EXPECT: sizeclass < 48",
                )
        else:
            P("Result of nontrivial_free()", white("Do nothing", bold=True))

        # dequeue
        if print_dq:
            print(green("  dequeue:", bold=True))
            prev_next = purple("*" + _hex(meta["prev"]["next"].address))
            prev_next = blue("prev->next(", bold=True) + prev_next + blue(")", bold=True)
            next_prev = purple("*" + _hex(meta["next"]["prev"].address))
            next_prev = blue("next->prev(", bold=True) + next_prev + blue(")", bold=True)
            next = blue("next(", bold=True) + purple(_hex(meta["next"])) + blue(")", bold=True)
            prev = blue("prev(", bold=True) + purple(_hex(meta["prev"])) + blue(")", bold=True)
            print("  \t%s = %s" % (prev_next, next))  # prev->next(XXX) = next(XXX)
            print("  \t%s = %s" % (next_prev, prev))  # next->prev(XXX) = prev(XXX)
        # free_group
        if print_fg:
            print(green("  free_group:", bold=True))
            if meta["maplen"]:
                free_method = "munmap (len=0x%lx)" % (int(meta["maplen"]) * 4096)
            else:
                free_method = "nontrivial_free()"
            print(
                " \t%s%s%s%s"
                % (
                    blue("group object at ", bold=True),
                    purple(_hex(["mem"])),
                    blue(" will be freed by ", bold=True),
                    cyan(free_method, bold=True),
                )
            )
        # free_meta
        if print_fm:
            print(green("  free_meta:", bold=True))
            print(
                " \t%s%s%s"
                % (
                    blue("meta object at ", bold=True),
                    purple(_hex(meta)),
                    blue(" will be freed and inserted into free_meta chain", bold=True),
                )
            )

    # Called by mslotinfo.
    def display_ib_slot(self, p: gdb.Value, meta: Dict, ib: Dict) -> None:
        """Display slot in-band information

        This expects the slot to be in-use and tries to parse it's in-band data.

        If the ib data isn't initialized yet, it will fail.
        """

        index = ib["index"]
        stride = self.get_stride(meta)
        slot_start = meta["mem"]["storage"][stride * index].address
        slot_end = slot_start + stride - mallocng.IB

        print(
            white("\n============= SLOT IN-BAND =============== ", bold=True)
            + "(at %s)" % _hex(slot_start)
        )
        bold_white = lambda s: white(s, bold=True)
        bold_blue = lambda s: blue(s, bold=True)
        printer = Printer(header_clr=bold_blue, content_clr=bold_white, header_rjust=20)
        P = printer.print

        # SLOT: Check cycling offset
        reserved_in_slot_head = (
            pwndbg.gdblib.memory.get_typed_pointer_value("uint8_t", slot_start - 3) & 0xE0
        ) >> 5
        if reserved_in_slot_head == 7:
            # If `R` is 7, it indicates that slot header is used to store cycling offset (in `OFF` field)
            # (See http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n217)
            cycling_offset = pwndbg.gdblib.memory.get_typed_pointer_value(
                "uint16_t", slot_start - 2
            )  # `OFF`
        else:
            # Else, slot header is now occupied by in-band meta.
            # In this case, `userdata` will be located at the beginning of slot.
            cycling_offset = 0
        userdata_ptr = slot_start + cycling_offset * mallocng.UNIT
        P(
            "cycling offset",
            "%s (userdata --> %s)" % (_hex(cycling_offset), _hex(userdata_ptr)),
        )

        # SLOT: Check reserved
        reserved_in_band = ib["reserved_in_band"]
        if reserved_in_band < 5:
            reserved = reserved_in_band
        elif reserved_in_band == 5:
            reserved_in_slot_end = pwndbg.gdblib.memory.get_typed_pointer_value(
                "uint32_t", slot_end - 4
            )
            if reserved_in_slot_end >= 5:
                reserved = reserved_in_slot_end
            else:
                P("reserved (slot end)", _hex(reserved_in_slot_end), "EXPECT: >= 5")
                reserved = -1
        else:
            P("reserved (in-band)", _hex(reserved_in_band), "EXPECT: <= 5")
            reserved = -1

        # SLOT: Check nominal size
        if reserved != -1:
            if reserved <= slot_end - p:
                nominal_size = slot_end - reserved - p
                P("nominal size", _hex(nominal_size))
                P("reserved size", _hex(reserved))
            else:
                P("nominal size", "N/A (reserved size is invaild)")
                P("reserved size", _hex(reserved), "EXPECT: <= %s" % _hex(slot_end - p))
                reserved = -1
        else:
            P("nominal size", "N/A (reserved size is invaild)")

        # SLOT: Check OVERFLOWs
        if reserved != -1:
            ud_overflow = pwndbg.gdblib.memory.get_typed_pointer_value(
                "uint8_t", slot_end - reserved
            )
            if not ud_overflow:
                P("OVERFLOW (user data)", 0)
            else:
                P(
                    "OVERFLOW (user data)",
                    _hex(ud_overflow),
                    "EXPECT: *(uint8_t*)(%s) == 0" % _hex(slot_end - reserved),
                )
            if reserved >= 5:
                rs_overflow = pwndbg.gdblib.memory.get_typed_pointer_value("uint8_t", slot_end - 5)
                if not rs_overflow:
                    P("OVERFLOW  (reserved)", 0)
                else:
                    P(
                        "OVERFLOW  (reserved)",
                        _hex(rs_overflow),
                        "EXPECT: *(uint8_t*)(%s) == 0" % _hex(slot_end - 5),
                    )
        else:
            P("OVERFLOW (user data)", "N/A (reserved size is invaild)")
            P("OVERFLOW  (reserved)", "N/A (reserved size is invaild)")
        ns_overflow = pwndbg.gdblib.memory.get_typed_pointer_value("uint8_t", slot_end)
        if not ns_overflow:
            P("OVERFLOW (next slot)", 0)
        else:
            P(
                "OVERFLOW (next slot)",
                _hex(ns_overflow),
                "EXPECT: *(uint8_t*)(%s) == 0" % _hex(slot_end),
            )
