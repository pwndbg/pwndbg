"""
Dynamic linking interface.

This module provides an interface to analyze various aspects of dynamically
linked programs.
"""

import gdb
import pwndbg.color.message as message
import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo
from pwndbg.lib.elftypes import constants as elf

def _r_debug():
    """
    The easiest entry point into the link map is through the debug structure
    provided by ld.so. It provides a convenient pointer into the head of the
    link map list[1], and can be found at the address that corresponds to the 
    `_r_debug` symbol[2].

    [1]: https://elixir.bootlin.com/glibc/latest/source/elf/link.h#L45
    [2]: https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-debug-symbols.S#L30
    """
    
    try:
        address = gdb.execute("output/x &_r_debug", to_string=True)
        address = int(address, 0)

        return address
    except gdb.error:
        # Symbol is most likely unavailable.
        return None


def link_map_head():
    """
    Acquires a reference to the head entry of the link map.
    """
    r_debug_address = _r_debug()
    if r_debug_address is None:
        print(message.warn("symbol _r_debug is missing, cannot find link map"))
        return None
    
    r_debug = CStruct.r_debug()

    r_version = r_debug.read(r_debug_address, "r_version")
    r_map = r_debug.read(r_debug_address, "r_map")

    print(f'_r_debug -> {r_debug_address:#x}')
    print(f'r_version = {r_version}')
    print(f'r_map = {r_map:#x}')

    if r_map != 0:
        return LinkMapEntry(r_map)

def link_map():
    """
    Iterator over all the entries in the link map.
    """
    head = link_map_head()
    while head is not None:
        yield head
        head = head.next()

class LinkMapEntry:
    """
    An entry in the link map.
    """
    def __init__(self, address):
        self.link_map = CStruct.link_map()
        self.link_map_address = address

    def name(self):
        """
        The name of the binary image this entry describes.
        """
        ptr = self.link_map.read(self.link_map_address, "l_name")
        return pwndbg.gdblib.memory.string(ptr)

    def dynamic(self):
        """
        The pointer to the memory mapped dynamic segment of the binary image.
        """
        return self.link_map.read(self.link_map_address, "l_ld")

    def load_bias(self):
        """
        The difference between the addresses in the data structures of the
        binary image and the actual location of the data being pointed to by
        them in the address space of the inferior. This number will never be
        negative.

        Aditionally, for DYN images, such as PIE executables and shared
        libraries, this value is the same as the base load address of the image.
        
        The term "load bias" comes from the ELF binary format loading procedure
        in the Linux Kernel.
        """
        return self.link_map.read(self.link_map_address, "l_addr")

    def next(self):
        """
        The next entry in the chain, if any.
        """
        ptr = self.link_map.read(self.link_map_address, "l_next")
        if ptr == 0:
            return None
        else:
            return LinkMapEntry(ptr)

    def prev(self):
        """
        The previous entry in the chain, if any.
        """
        ptr = self.link_map.read(self.link_map_address, "l_prev")
        if ptr == 0:
            return None
        else:
            return LinkMapEntry(ptr)

    def __repr__(self):
        return f"<{self.__class__.__name__} node={self.link_map_address:#x} name={self.name()} load_bias={self.load_bias():#x} dynamic={self.dynamic():#x}>"

DYNAMIC_SECTION_INIT_TAGS = set([
    elf.DT_STRTAB,
    elf.DT_STRSZ,
])

class DynamicSegment:
    """
    """

    def __init__(self, address, load_bias):
        # Enumerate the ElfNN_Dyn entries.
        count = 0
        elf_dyn = CStruct.elfNN_dyn()

        while elf_dyn.read(address + count * elf_dyn.size, "d_tag") != elf.DT_NULL:
            count += 1

        # Set up the fields used by the methods we use next.
        self.entries = count
        self.address = address
        self.load_bias = load_bias
        self.elf_dyn = elf_dyn

        # Map the tags we want to find to their respective entires. We don't
        # allow for repeats as the tags should only appear once in a well-formed
        # dynamic segment.
        sections = {}
        for i in range(self.entries):
            tag = self.dyn_array_read(i, "d_tag")
            if tag not in DYNAMIC_SECTION_INIT_TAGS:
                continue
            if tag in sections:
                raise RuntimeError(f"tag {tag:#x} repeated in DYNAMIC segment")
            sections[tag] = i
        for tag in DYNAMIC_SECTION_INIT_TAGS:
            if tag not in sections:
                raise RuntimeError(f"DYNAMIC segment missing requried tag {tag:#x}")

        # Setup the string table reference.
        self.strtab_addr = self.dyn_array_read(sections[elf.DT_STRTAB], "d_un")
        self.strtab_size = self.dyn_array_read(sections[elf.DT_STRSZ], "d_un")
    
    def string(self, i):
        """
        Reads the string at index i from the string table.
        """
        if i >= self.strtab_size:
            raise ValueError(f"tried to read entry {i} in string table with only {self.entries} bytes")
        return pwndbg.gdblib.memory.string(self.strtab_addr + i)

    def dyn_array_read(self, i, field):
        """
        Reads the requested field from the entry of given index in the dynamic
        array.
        """
        if i >= self.entries:
            raise ValueError(f"tried to read from entry {i} in dynamic array with only {self.entries} entries")
        return self.elf_dyn.read(self.address + i * self.elf_dyn.size, field)

class CStruct:
    """
    Utility class for reading fields off of C structs. 

    Without proper debug information it cannot be guaranteed that the calculated
    field offsets are correct, therefore, reasonable caution should be exercised
    when using this class. The assumptions made are:
     - Padding is added between fields so that all internal members are
       correctly aligned, as long as the struct itself is correctly aligned.
     - The alignment of the struct is the same as the alignment of its most
       strictly aligned member.
     - Padding is added to the end of the struct so that sequentially laid out
       instances are always correctly aligned.
     - Stuct sizes must be greater than or equal to 1 byte.

    While these assumptions do not apply in all cases, they should be good
    enough for the structs in ld.so and in the ELF program images.
    """

    types = {}
    offsets = {}
    converters = {}
    size = 0
    align = 0

    def link_map():
        """
        Creates a new instance describing the ABI-stable part of the link_map
        struct.
        """
        return CStruct([
            ("l_addr", pwndbg.gdblib.typeinfo.size_t, int),
            ("l_name", pwndbg.gdblib.typeinfo.char.pointer(), int),
            ("l_ld", pwndbg.gdblib.typeinfo.pvoid, int),
            ("l_next", pwndbg.gdblib.typeinfo.pvoid, int),
            ("l_prev", pwndbg.gdblib.typeinfo.pvoid, int),
        ])

    def r_debug():
        """
        Creates a new instance describing the ABI-stable part of the r_debug
        struct.
        """
        return CStruct([
            ("r_version", pwndbg.gdblib.typeinfo.uint, int),
            ("r_map", pwndbg.gdblib.typeinfo.pvoid, int)
        ])

    def elfNN_dyn():
        """
        Creates a new instance describing the ElfNN_Dyn structure, suitable for
        the architecture of the inferior.
        """
        return CStruct([
            ("d_tag", pwndbg.gdblib.typeinfo.size_t, int),
            ("d_un", pwndbg.gdblib.typeinfo.size_t, int)
        ])

    def __init__(self, fields):
        # Calculate the offset of all of the fields in the struct.
        current_offset = 0
        alignment = 1
        for entry in fields:
            name = entry[0]
            ty = entry[1]
            if len(entry) > 2:
                conv = entry[2]
            else:
                conv = None

            # Pad the offset so that the field is correctly aligned.
            if current_offset % ty.alignof != 0:
                current_offset += ty.alignof - (current_offset % ty.alignof)

            # Save the alignment requirements of the strictest element.
            if ty.alignof > alignment:
                alignment = ty.alignof

            self.offsets[name] = current_offset
            self.types[name] = ty
            self.converters[name] = conv

            current_offset += ty.sizeof

        # We don't consider zero-sized structures to be valid.
        if current_offset == 0:
            current_offset = 1

        # Pad the end of the struct so that the next instance of this struct in
        # an array is correctly aligned.
        if current_offset % alignment != 0:
            current_offset += alignment - (current_offset % alignment)

        self.size = current_offset
        self.align = alignment
    
    def read(self, address, name):
        """
        Reads the field with the given name from the struct instance located at
        the given address.
        """
        val = pwndbg.gdblib.memory.poi(self.types[name], address + self.offsets[name])
        if self.converters[name] is not None:
            return self.converters[name](val)
        else:
            return val


