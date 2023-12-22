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


# Normally, only one entry for each tag is allowed to be present in the dynamic
# array for us to consider the dynamic array to be well-formed. Tags in this
# set are allowed to appear multiple times.
DYNAMIC_SECTION_ALLOW_MULTIPLE = set([
    elf.DT_NEEDED
])

# The DynamicSegment class expects some tags to always be present to function
# correctly. In this set we list them explicitly. Code in that class is allowed
# to presume these tags are always present after __init__.
DYNAMIC_SECTION_REQUIRED_TAGS = set([
    elf.DT_STRTAB,
    elf.DT_STRSZ,
    elf.DT_SYMTAB,
    elf.DT_SYMENT,
])

class DynamicSegment:
    """
    """
    
    strtab_addr = 0
    strtab_size = 0

    entries_by_tag = {}

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
            if tag in sections:
                if tag not in DYNAMIC_SECTION_ALLOW_MULTIPLE:
                   raise RuntimeError(f"tag {tag:#x} repeated in DYNAMIC segment")

                if isinstance(sections[tag], list):
                    sections[tag].append(i)
                else:
                    sections[tag] = [sections[tag], i]
            else:
                sections[tag] = i
        for tag in DYNAMIC_SECTION_INIT_TAGS:
            if tag not in sections:
                raise RuntimeError(f"DYNAMIC segment missing requried tag {tag:#x}")
        self.entries_by_tag = sections

        # Setup the string table reference.
        self.strtab_addr = self.dyn_array_read(sections[elf.DT_STRTAB], "d_un")
        self.strtab_size = self.dyn_array_read(sections[elf.DT_STRSZ], "d_un")
        self.symtab_addr = self.dyn_array_read(sections[elf.DT_SYMTAB], "d_un")
        self.symtab_elem = self.dyn_array_read(sections[elf.DT_SYMENT], "d_un")

    def has_jmprel(self):
        """
        Whether this segment has a DT_JMPREL entry.
        """
        return (
            elf.DT_JMPREL   in self.entries_by_tag and
            elf.DT_PLTREL   in self.entries_by_tag and
            elf.DT_PLTRELSZ in self.entries_by_tag
        )

    def plt_rel(self):
        """
        Reads t
        """

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

    def elfNN_sym():
        """
        Creates a new instance describing the ElfNN_Sym structure, suitable for
        the architecture of the inferior.
        """

        # The layouts used by this struct differ between ELF32 and ELF64, so we
        # have to pick the right class for the current architecture. It just so
        # happens that this is one bit of information that can't be gathered
        # directly from the dynamic section.
        #
        # Interestngly for us, however, `ld.so` can get away with having just
        # one version of all of its structures, which means it can only support
        # one class per target, and won't allow for a single process to dlload()
        # multiple classes. Indeed, it defines a macro called __ELF_NATIVE_CLASS
        # which effectively hard-codes the expected ELF class for the dynamic
        # linker, and refuses to load libraries of another class[1].
        #
        # While we can't know what the __ELF_NATIVE_CLASS is, directly, we can
        # use the pointer size of the system as a good enough proxy. And,
        # because all structures in `ld.so` are bound to a given ELF class, we
        # can assume that the structure belonging to the native class is the
        # correct one to pick here.
        #
        # TODO: Is there any important case where this could be false?
        #
        # [1]: https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/readelflib.c#L58
        from pwndbg.gdblib.typeinfo import ptrsize

        if ptrsize == 4:
            return elf32_sym()
        elif ptrsize == 8:
            return elf64_sym()
        else:
            raise RuntimeError(f"unsupported pointer size {ptrsize}")

    def elf32_sym():
        # FIXME: ELF types have an exact size. We want our GDB types to match
        # whatever the platform's exact sized integer types are, but, because of
        # how these types are resolved, that might not always be the case.
        #
        # It's better to fail loudly here than to fail silently later.
        assert pwndbg.gdblib.typeinfo.uint32.sizeof == 4
        assert pwndbg.gdblib.typeinfo.uint16.sizeof == 2
        assert pwndbg.gdblib.typeinfo.uint8.sizeof == 1

        return CStruct([
            ("st_name",  pwndbg.gdblib.typeinfo.uint32, int),
            ("st_value", pwndbg.gdblib.typeinfo.uint32, int),
            ("st_size",  pwndbg.gdblib.typeinfo.uint32, int),
            ("st_info",  pwndbg.gdblib.typeinfo.uint8, int),
            ("st_other", pwndbg.gdblib.typeinfo.uint8, int),
            ("st_shndx", pwndbg.gdblib.typeinfo.uint16, int)
        ])

    def elf64_sym():
        # FIXME: Same issue as elf32_sym()
        assert pwndbg.gdblib.typeinfo.uint.sizeof == 8
        assert pwndbg.gdblib.typeinfo.uint32.sizeof == 4
        assert pwndbg.gdblib.typeinfo.uint16.sizeof == 2
        assert pwndbg.gdblib.typeinfo.uint8.sizeof == 1

        return CStruct([
            ("st_name",  pwndbg.gdblib.typeinfo.uint32, int),
            ("st_info",  pwndbg.gdblib.typeinfo.uint8, int),
            ("st_other", pwndbg.gdblib.typeinfo.uint8, int),
            ("st_shndx", pwndbg.gdblib.typeinfo.uint16, int)
            ("st_value", pwndbg.gdblib.typeinfo.uint64, int),
            ("st_size",  pwndbg.gdblib.typeinfo.uint64, int),
        ])


    def __init__(self, fields):
        # Calculate the offset of all of the fields in the struct.
        current_offset = 0
        alignment = 1
        for entry in fields:
            name = entry[0]
            22ty = entry[1]
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


