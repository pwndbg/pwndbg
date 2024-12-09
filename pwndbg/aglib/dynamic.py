"""
Dynamic linking interface.

This module provides an interface to analyze various aspects of dynamically
linked programs.

It also defines a hook that watches for changes to the link map communicated by
ld.so, and exposes an event that other parts of pwndbg can tap into, but one
that may have a somewhat obtuse beahvior, due to limitations in GDB. See
`r_debug_install_link_map_changed_hook` for more information.
"""

from __future__ import annotations

from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.color.message as message
import pwndbg.lib.cache
from pwndbg.lib.elftypes import constants as elf


def _r_debug() -> int | None:
    """
    The easiest entry point into the link map is through the debug structure
    provided by ld.so. It provides a convenient pointer into the head of the
    link map list[1], and can be found at the address that corresponds to the
    `_r_debug` symbol[2].

    [1]: https://elixir.bootlin.com/glibc/latest/source/elf/link.h#L45
    [2]: https://elixir.bootlin.com/glibc/glibc-2.38/source/elf/dl-debug-symbols.S#L30
    """

    return pwndbg.aglib.symbol.lookup_symbol_addr("_r_debug")


def is_dynamic() -> bool:
    """
    Returns whether the current inferior is dynamic.

    Not all programs are dynamically linked, or even need the dynamic loader at
    all. Since this module is entirely reliant on at least the presence of the
    dynamic loader, and really only makes sense for dynamic programs, it should
    not be used at all with programs that don't participate in dynamic linkage,
    or when there is a dynamic linker, but we have no way to talk to it.
    """
    return _r_debug() is not None


# Reference to our hook in the link map update breakpoint, if it is installed.
R_DEBUG_LINK_MAP_CHANGED_HOOK = None
R_DEBUG_LINK_MAP_CHANGED_LISTENERS: Set[Callable[..., Any]] = set()


def r_debug_link_map_changed_hook() -> Callable[[pwndbg.dbg_mod.StopPoint], bool]:
    """
    Hook that gets activated whenever the link map changes.

    The r_debug structure, in addition to having a refence to the head of the
    link map, also has, in its ABI-stable part, a reference to an address that
    can have a breakpoint attached to it, such that whenever the contents of the
    link map change, that breakpoint will be triggered[1].

    We take advantage of that here, by installing our own breakpoint in that
    location, and watching for trigger events, so that we can notify other bits
    of pwndbg that the contents of the `link_map()` function will be different.

    [1]: https://elixir.bootlin.com/glibc/glibc-2.37/source/elf/link.h#L52
    """

    skip_this = True

    def hook(_bp: pwndbg.dbg_mod.StopPoint) -> bool:
        # Skip every other trigger, we only care about the completed link map
        # that is available after the library is loaded.
        nonlocal skip_this
        if not skip_this:
            # Clear the cache that is tied to link map updates, and signal all of
            # the interested parties that this event has occurred.
            for listener in R_DEBUG_LINK_MAP_CHANGED_LISTENERS:
                listener()
        skip_this = not skip_this

        return False

    return hook


# FIXME: Obviously, having consumers call this function is not ideal. We really
# should find a way to install this automatically at the correct time. What we
# want is something that can run some arbitrary Python code at the same point
# in the lifecycle of the inferior as the user would be put in if they were to
# run `stepi`.
def r_debug_install_link_map_changed_hook() -> None:
    """
    Installs the r_debug-based hook to the change event of the link map.

    This function is a bit tricky, because ideally we want it to be run as
    soon as possible, before even the dynamic linker runs, but after both it and
    the main binary have been mapped into the address space of the inferior.
    While doing this manually would be trivial - seeing as there is a command
    in GDB that gives the user control at the exact place we would like -, there
    does not seem to be a way of easily doing this from inside Python.

    Because of this, parts of the code that rely on the hook should try calling
    this function and firing their own listeners manually at least once.
    """
    # TODO: Currently, reacting to this event has some unpleasant side effects
    # on usability. Until this can be fixed, this hook is unavailable.
    print(
        message.warn("r_brk hook is disabled. r_debug_install_link_map_changed_hook() does nothing")
    )
    return

    global R_DEBUG_LINK_MAP_CHANGED_HOOK
    if R_DEBUG_LINK_MAP_CHANGED_HOOK is not None:
        return

    r_debug_address = _r_debug()
    if r_debug_address is None:
        print(message.warn("symbol _r_debug is missing, cannot install link map change hook"))
        return

    r_debug = CStruct.r_debug()
    r_brk = r_debug.read(r_debug_address, "r_brk")

    bp = pwndbg.dbg.selected_inferior().break_at(
        pwndbg.dbg_mod.BreakpointLocation(r_brk),
        stop_hook=r_debug_link_map_changed_hook(),
        internal=True,
    )

    R_DEBUG_LINK_MAP_CHANGED_HOOK = bp


def r_debug_link_map_changed_add_listener(handler: Callable[..., Any]) -> None:
    """
    Install a callback to be called whenever r_debug signal of there being a
    change in the link map link map is triggered.

    Keep in mind this function may be called before the hook that calls the
    listeners is installed, and, until it is installed, no listener callbacks
    will actually be triggered. See `r_debug_install_link_map_changed_hook`.
    """
    R_DEBUG_LINK_MAP_CHANGED_LISTENERS.add(handler)


def r_debug_link_map_changed_remove_listener(handler: Callable[..., Any]) -> None:
    """
    Removes a listener previously installed with
    r_debug_link_map_changed_add_listener().
    """
    R_DEBUG_LINK_MAP_CHANGED_LISTENERS.remove(handler)


def link_map_head():
    """
    Acquires a reference to the head entry of the link map.
    """
    r_debug_address = _r_debug()
    if r_debug_address is None:
        print(message.warn("symbol _r_debug is missing, cannot find link map"))
        return None

    r_debug = CStruct.r_debug()

    r_map = r_debug.read(r_debug_address, "r_map")

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

    def __init__(self, address) -> None:
        self.link_map = CStruct.link_map()
        self.link_map_address = address

    def name(self):
        """
        The name of the binary image this entry describes.
        """
        ptr = self.link_map.read(self.link_map_address, "l_name")
        return pwndbg.aglib.memory.string(ptr)

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

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} node={self.link_map_address:#x} name={self.name()} load_bias={self.load_bias():#x} dynamic={self.dynamic():#x}>"


# Normally, only one entry for each tag is allowed to be present in the dynamic
# array for us to consider the dynamic array to be well-formed. Tags in this
# set are allowed to appear multiple times.
DYNAMIC_SECTION_ALLOW_MULTIPLE = {elf.DT_NEEDED}

# The DynamicSegment class expects some tags to always be present to function
# correctly. In this set we list them explicitly. Code in that class is allowed
# to presume these tags are always present after __init__.
DYNAMIC_SECTION_REQUIRED_TAGS = {
    elf.DT_STRTAB,
    elf.DT_STRSZ,
    elf.DT_SYMTAB,
    elf.DT_SYMENT,
}


class DynamicSegment:
    """
    Parser for the DYNAMIC segment present in a binary image.
    """

    strtab_addr = 0
    strtab_size = 0

    symtab_addr = 0
    symtab_elem = None

    entries_by_tag: Dict[Any, Any] = {}

    has_jmprel = False
    has_rela = False
    has_rel = False

    jmprel_addr = 0
    rela_addr = 0
    rel_addr = 0

    jmprel_elem = None
    rela_elem = None
    rel_elem = None

    jmprel_r_sym_fn = None
    jmprel_r_info_fn = None

    rela_r_sym_fn = None
    rela_r_info_fn = None

    rel_r_sym_fn = None
    rel_r_info_fn = None

    def __init__(self, address, load_bias) -> None:
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
        # allow for repeats on most tags as they should only appear once in a
        # well-formed dynamic segment.
        sections: Dict[Any, Any] = {}
        for i in range(self.entries):
            tag = self.dyn_array_read(i, "d_tag")
            if tag in sections:
                if tag not in DYNAMIC_SECTION_ALLOW_MULTIPLE:
                    raise RuntimeError(f"tag {tag:#x} repeated")

                if isinstance(sections[tag], list):
                    sections[tag].append(i)
                else:
                    sections[tag] = [sections[tag], i]
            else:
                sections[tag] = i
        for tag in DYNAMIC_SECTION_REQUIRED_TAGS:
            if tag not in sections:
                raise RuntimeError(f"missing requried tag {tag:#x}")
        self.entries_by_tag = sections

        # Setup the string table reference.
        self.strtab_addr = self.dyn_array_read_tag_val(elf.DT_STRTAB)
        self.strtab_size = self.dyn_array_read_tag_val(elf.DT_STRSZ)

        # Find the address of the symbol table and determine the correct version
        # of the ElfNN_Sym structure to use for this table, based on the size
        # of the elements given by DT_SYMENT.
        self.symtab_addr = self.dyn_array_read_tag_val(elf.DT_SYMTAB)

        syment = self.dyn_array_read_tag_val(elf.DT_SYMENT)
        if syment == 16:
            self.symtab_elem = CStruct.elf32_sym()
        elif syment == 24:
            self.symtab_elem = CStruct.elf64_sym()
        else:
            raise RuntimeError(
                f"unsupported value {syment} for DT_SYMENT, expected either 16 (Elf32_Sym) or 24 (Elf64_Sym)"
            )

        # Check the relocation sections, and perform some sanity checks.
        self.has_jmprel = (
            elf.DT_JMPREL in sections and elf.DT_PLTREL in sections and elf.DT_PLTRELSZ in sections
        )
        self.has_rela = (
            elf.DT_RELA in sections and elf.DT_RELASZ in sections and elf.DT_RELAENT in sections
        )
        self.has_rel = (
            elf.DT_REL in sections and elf.DT_RELSZ in sections and elf.DT_RELENT in sections
        )

        # Create the CStructs for the entries in each of our relocation sections
        # and make sure that their size matches the value of their respective
        # dynamic array element size entry. Additionally, pick selectors for
        # r_sym and r_type based on the size of the element of each of the
        # relocation sections.
        if self.has_rela:
            self.rela_addr = self.dyn_array_read_tag_val(elf.DT_RELA)
            self.rela_elem = CStruct.elfNN_rela()
            relaent = self.dyn_array_read_tag_val(elf.DT_RELAENT)
            assert self.rela_elem.size == relaent

            if self.dyn_array_read_tag_val(elf.DT_RELASZ) % self.rela_elem.size != 0:
                raise RuntimeError("DT_RELASZ is not divisible by DT_RELAENT")

            if self.rela_elem.size == 12:
                self.rela_r_sym = elf32_r_sym
                self.rela_r_type = elf32_r_type
            elif self.rela_elem.size == 24:
                self.rela_r_sym = elf64_r_sym
                self.rela_r_type = elf64_r_type
            else:
                raise RuntimeError(
                    f"DT_RELAENT is {self.rela_elem}, expected 12 (ELF32) or 24 (ELF64)"
                )

        if self.has_rel:
            self.rel_addr = self.dyn_array_read_tag_val(elf.DT_REL)
            self.rel_elem = CStruct.elfNN_rel()
            relent = self.dyn_array_read_tag_val(elf.DT_RELENT)
            assert self.rel_elem.size == relent

            if self.dyn_array_read_tag_val(elf.DT_RELSZ) % self.rel_elem.size != 0:
                raise RuntimeError("DT_RELSZ is not divisible by DT_RELENT")

            if self.rel_elem.size == 8:
                self.rel_r_sym = elf32_r_sym
                self.rel_r_type = elf32_r_type
            elif self.rel_elem.size == 16:
                self.rel_r_sym = elf64_r_sym
                self.rel_r_type = elf64_r_type
            else:
                raise RuntimeError(
                    f"DT_RELENT is {self.rel_elem}, expected 8 (ELF32) or 16 (ELF64)"
                )

        if self.has_jmprel:
            self.jmprel_addr = self.dyn_array_read_tag_val(elf.DT_JMPREL)
            pltrel = self.dyn_array_read_tag_val(elf.DT_PLTREL)
            if pltrel == elf.DT_RELA:
                self.jmprel_elem = CStruct.elfNN_rela()
                if elf.DT_RELAENT not in sections:
                    raise RuntimeError("DT_PLTREL is DT_RELA, but missing DT_RELAENT")
                assert self.jmprel_elem.size == self.dyn_array_read_tag_val(elf.DT_RELAENT)

                if self.rela_elem.size == 12:
                    self.jmprel_r_sym = elf32_r_sym
                    self.jmprel_r_type = elf32_r_type
                elif self.rela_elem.size == 24:
                    self.jmprel_r_sym = elf64_r_sym
                    self.jmprel_r_type = elf64_r_type
                else:
                    raise RuntimeError(
                        f"DT_RELAENT is {self.rela_elem}, expected 12 (ELF32) or 24 (ELF64)"
                    )

            elif pltrel == elf.DT_REL:
                self.jmprel_elem = CStruct.elfNN_rel()
                if elf.DT_RELENT not in sections:
                    raise RuntimeError("DT_PLTREL is DT_REL, but missing DT_RELENT")
                assert self.jmprel_elem.size == self.dyn_array_read_tag_val(elf.DT_RELENT)

                if self.jmprel_elem.size == 8:
                    self.jmprel_r_sym = elf32_r_sym
                    self.jmprel_r_type = elf32_r_type
                elif self.jmprel_elem.size == 16:
                    self.jmprel_r_sym = elf64_r_sym
                    self.jmprel_r_type = elf64_r_type
                else:
                    raise RuntimeError(
                        f"DT_RELENT is {self.rel_elem}, expected 8 (ELF32) or 16 (ELF64)"
                    )

            if self.dyn_array_read_tag_val(elf.DT_PLTRELSZ) % self.jmprel_elem.size != 0:
                raise RuntimeError("DT_PLTRELSZ is not divisible by the element size")

    def jmprel_has_addend(self):
        """
        Returns whether the `r_addend` field is available in entries of JMPREL.
        """
        assert self.has_jmprel
        return self.dyn_array_read_tag_val(elf.DT_PLTREL) == elf.DT_RELA

    def rela_read(self, i, field):
        """
        Reads the requested field from the entry of the given index in RELA.
        """
        assert self.has_rela
        count = self.rela_entry_count()
        if i >= count:
            raise ValueError(f"tried to read entry {i} in RELA with only {count} entries")

        transform = lambda x: x
        if field == "r_sym":
            transform = self.rela_r_sym
            field = "r_info"
        elif field == "r_type":
            transform = self.rela_r_type
            field = "r_info"

        return transform(self.rela_elem.read(self.rela_addr + i * self.rela_elem.size, field))

    def rel_read(self, i, field):
        """
        Reads the requested field from the entry of the given index in REL.
        """
        assert self.has_rel
        count = self.rel_entry_count()
        if i >= count:
            raise ValueError(f"tried to read entry {i} in REL with only {count} entries")

        transform = lambda x: x
        if field == "r_sym":
            transform = self.rel_r_sym
            field = "r_info"
        elif field == "r_type":
            transform = self.rel_r_type
            field = "r_info"

        return transform(self.rel_elem.read(self.rel_addr + i * self.rel_elem.size, field))

    def jmprel_read(self, i, field):
        """
        Reads the requested field from the entry of the given index in JMPREL.
        """
        assert self.has_jmprel
        count = self.jmprel_entry_count()
        if i >= count:
            raise ValueError(f"tried to read entry {i} in JMPREL with only {count} entries")

        transform = lambda x: x
        if field == "r_sym":
            transform = self.jmprel_r_sym
            field = "r_info"
        elif field == "r_type":
            transform = self.jmprel_r_type
            field = "r_info"

        return transform(self.jmprel_elem.read(self.jmprel_addr + i * self.jmprel_elem.size, field))

    def rela_entry_count(self):
        """
        Returns the number of RELA entries.
        """
        assert self.has_rela
        relasz = self.dyn_array_read_tag_val(elf.DT_RELASZ)
        relaent = self.dyn_array_read_tag_val(elf.DT_RELAENT)

        return relasz // relaent

    def rel_entry_count(self):
        """
        Returns the number of REL entries.
        """
        assert self.has_rel
        relsz = self.dyn_array_read_tag_val(elf.DT_RELSZ)
        relent = self.dyn_array_read_tag_val(elf.DT_RELENT)

        return relsz // relent

    def jmprel_entry_count(self):
        """
        Returns the number of JMPREL entries.
        """
        assert self.has_jmprel
        pltrelsz = self.dyn_array_read_tag_val(elf.DT_PLTRELSZ)
        pltrelent = self.jmprel_elem.size

        return pltrelsz // pltrelent

    def string(self, i):
        """
        Reads the string at index i from the string table.
        """
        if i >= self.strtab_size:
            raise ValueError(
                f"tried to read entry {i} in string table with only {self.entries} bytes"
            )
        return pwndbg.aglib.memory.string(self.strtab_addr + i)

    def symtab_read(self, i, field):
        """
        Reads the requested field from the entry of given index in the symbol
        table.
        """
        return self.symtab_elem.read(self.symtab_addr + i * self.symtab_elem.size, field)

    def dyn_array_read(self, i, field):
        """
        Reads the requested field from the entry of given index in the dynamic
        array.
        """
        if i >= self.entries:
            raise ValueError(
                f"tried to read from entry {i} in dynamic array with only {self.entries} entries"
            )
        return self.elf_dyn.read(self.address + i * self.elf_dyn.size, field)

    def dyn_array_read_tag_val(self, tag):
        """
        Reads the `d_un` field from the entry of given tag in the dynamic
        array. Must not be a tag that allows multiple entries.
        """
        return self.dyn_array_read(self.entries_by_tag[tag], "d_un")


def elf32_r_sym(r_info):
    """
    Returns the r_sym portion of the r_info relocation field for ELF32.
    """
    return (r_info >> 8) & 0xFFFFFF


def elf32_r_type(r_info):
    """
    Returns the r_type portion of the r_info relocation field for ELF32.
    """
    return r_info & 0xFF


def elf64_r_sym(r_info):
    """
    Returns the r_sym portion of the r_info relocation field for ELF64.
    """
    return (r_info >> 32) & 0xFFFFFFFF


def elf64_r_type(r_info):
    """
    Returns the r_type portion of the r_info relocation field for ELF64.
    """
    return r_info & 0xFFFFFFFF


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

    types: Dict[str, pwndbg.dbg_mod.Type] = {}
    offsets: Dict[str, int] = {}
    converters: Dict[str, type] = {}
    size = 0
    align = 0

    @staticmethod
    def link_map():
        """
        Creates a new instance describing the ABI-stable part of the link_map
        struct.
        """
        return CStruct(
            [
                ("l_addr", pwndbg.aglib.typeinfo.size_t, int),
                ("l_name", pwndbg.aglib.typeinfo.char.pointer(), int),
                ("l_ld", pwndbg.aglib.typeinfo.pvoid, int),
                ("l_next", pwndbg.aglib.typeinfo.pvoid, int),
                ("l_prev", pwndbg.aglib.typeinfo.pvoid, int),
            ]
        )

    @staticmethod
    def r_debug():
        """
        Creates a new instance describing the ABI-stable part of the r_debug
        struct.
        """
        return CStruct(
            [
                ("r_version", pwndbg.aglib.typeinfo.uint, int),
                ("r_map", pwndbg.aglib.typeinfo.pvoid, int),
                ("r_brk", pwndbg.aglib.typeinfo.pvoid, int),
            ]
        )

    @staticmethod
    def elfNN_dyn():
        """
        Creates a new instance describing the ElfNN_Dyn structure, suitable for
        the architecture of the inferior.
        """
        return CStruct(
            [
                ("d_tag", pwndbg.aglib.typeinfo.size_t, int),
                ("d_un", pwndbg.aglib.typeinfo.size_t, int),
            ]
        )

    @staticmethod
    def elfNN_rel():
        """
        Creates a new instance describing the ElfNN_Rel structure, suitable for
        the architecture of the inferior.
        """
        return CStruct(
            [
                ("r_offset", pwndbg.aglib.typeinfo.size_t, int),
                ("r_info", pwndbg.aglib.typeinfo.size_t, int),
            ]
        )

    @staticmethod
    def elfNN_rela():
        """
        Creates a new instance describing the ElfNN_Rela structure, suitable for
        the architecture of the inferior.
        """
        return CStruct(
            [
                ("r_offset", pwndbg.aglib.typeinfo.size_t, int),
                ("r_info", pwndbg.aglib.typeinfo.size_t, int),
                ("r_addend", pwndbg.aglib.typeinfo.size_t, int),
            ]
        )

    @staticmethod
    def elf32_sym():
        """
        Creates a new instance describing the Elf32_Sym srtucture.
        """
        # FIXME: ELF types have an exact size. We want our GDB types to match
        # whatever the platform's exact sized integer types are, but, because of
        # how these types are resolved, that might not always be the case.
        #
        # It's better to fail loudly here than to fail silently later.
        assert pwndbg.aglib.typeinfo.uint32.sizeof == 4
        assert pwndbg.aglib.typeinfo.uint16.sizeof == 2
        assert pwndbg.aglib.typeinfo.uint8.sizeof == 1

        return CStruct(
            [
                ("st_name", pwndbg.aglib.typeinfo.uint32, int),
                ("st_value", pwndbg.aglib.typeinfo.uint32, int),
                ("st_size", pwndbg.aglib.typeinfo.uint32, int),
                ("st_info", pwndbg.aglib.typeinfo.uint8, int),
                ("st_other", pwndbg.aglib.typeinfo.uint8, int),
                ("st_shndx", pwndbg.aglib.typeinfo.uint16, int),
            ]
        )

    @staticmethod
    def elf64_sym():
        """
        Creates a new instance describing the Elf64_Sym structure.
        """

        # FIXME: Same issue as elf32_sym()
        assert pwndbg.aglib.typeinfo.uint64.sizeof == 8
        assert pwndbg.aglib.typeinfo.uint32.sizeof == 4
        assert pwndbg.aglib.typeinfo.uint16.sizeof == 2
        assert pwndbg.aglib.typeinfo.uint8.sizeof == 1

        return CStruct(
            [
                ("st_name", pwndbg.aglib.typeinfo.uint32, int),
                ("st_info", pwndbg.aglib.typeinfo.uint8, int),
                ("st_other", pwndbg.aglib.typeinfo.uint8, int),
                ("st_shndx", pwndbg.aglib.typeinfo.uint16, int),
                ("st_value", pwndbg.aglib.typeinfo.uint64, int),
                ("st_size", pwndbg.aglib.typeinfo.uint64, int),
            ]
        )

    def __init__(self, fields: List[Tuple[str, pwndbg.dbg_mod.Type, type]]) -> None:
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
        val = pwndbg.aglib.memory.get_typed_pointer_value(
            self.types[name], address + self.offsets[name]
        )
        if self.converters[name] is not None:
            return self.converters[name](val)
        else:
            return val

    def has_field(self, name) -> bool:
        """
        Returns whether a field with the given name exists in this struct.
        """
        return name in self.offsets
