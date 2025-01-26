"""
This file declares types and methods useful for enumerating
all of the address spaces and permissions of an ELF file in memory.

This is necessary for when access to /proc is restricted, or when
working on a BSD system which simply does not have /proc.
"""

from __future__ import annotations

import ctypes
import importlib
import sys
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Tuple
from typing import TypeVar
from typing import Union

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import Relocation
from elftools.elf.relocation import RelocationSection

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.ctypes
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.symbol
import pwndbg.aglib.vmmap
import pwndbg.auxv
import pwndbg.lib.cache
import pwndbg.lib.elftypes
import pwndbg.lib.memory
from pwndbg.color import message
from pwndbg.dbg import EventType

# ELF constants
PF_X, PF_W, PF_R = 1, 2, 4
ET_EXEC, ET_DYN = 2, 3


module = sys.modules[__name__]


class ELFInfo(NamedTuple):
    """
    ELF metadata and structures.
    """

    header: Dict[str, int | str]
    sections: List[Dict[str, int | str]]
    segments: List[Dict[str, int | str]]

    @property
    def is_pic(self) -> bool:
        return self.header["e_type"] == "ET_DYN"

    @property
    def is_pie(self) -> bool:
        return self.is_pic


Ehdr = Union[pwndbg.lib.elftypes.Elf32_Ehdr, pwndbg.lib.elftypes.Elf64_Ehdr]
Phdr = Union[pwndbg.lib.elftypes.Elf32_Phdr, pwndbg.lib.elftypes.Elf64_Phdr]


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def update() -> None:
    global Ehdr, Phdr
    try:
        importlib.reload(pwndbg.lib.elftypes)

    except ImportError:
        print(message.warn("Failed to reload pwndbg.lib.elftypes"))
        pass

    if pwndbg.aglib.arch.ptrsize == 4:
        Ehdr = pwndbg.lib.elftypes.Elf32_Ehdr
        Phdr = pwndbg.lib.elftypes.Elf32_Phdr
    else:
        Ehdr = pwndbg.lib.elftypes.Elf64_Ehdr
        Phdr = pwndbg.lib.elftypes.Elf64_Phdr

    module.__dict__.update(locals())


T = TypeVar(
    "T",
    Union[pwndbg.lib.elftypes.Elf32_Ehdr, pwndbg.lib.elftypes.Elf64_Ehdr],
    Union[pwndbg.lib.elftypes.Elf32_Phdr, pwndbg.lib.elftypes.Elf64_Phdr],
)


def read(typ: T, address: int, blob: bytearray | None = None) -> T:
    size = ctypes.sizeof(typ)

    if not blob:
        data = pwndbg.aglib.memory.read(address, size)
    else:
        data = blob[address : address + size]

    obj = typ.from_buffer_copy(data)
    obj.address = address
    obj.type = typ
    return obj


@pwndbg.lib.cache.cache_until("objfile")
def get_elf_info(filepath: str) -> ELFInfo:
    """
    Parse and return ELFInfo.

    Adds various calculated properties to the ELF header, segments and sections.
    Such added properties are those with prefix 'x_' in the returned dicts.
    """
    local_path = pwndbg.aglib.file.get_file(filepath)
    with open(local_path, "rb") as f:
        elffile = ELFFile(f)
        header = dict(elffile.header)
        segments = []
        for seg in elffile.iter_segments():
            s = dict(seg.header)
            s["x_perms"] = [
                mnemonic
                for mask, mnemonic in [(PF_R, "read"), (PF_W, "write"), (PF_X, "execute")]
                if s["p_flags"] & mask != 0
            ]
            # end of memory backing
            s["x_vaddr_mem_end"] = s["p_vaddr"] + s["p_memsz"]
            # end of file backing
            s["x_vaddr_file_end"] = s["p_vaddr"] + s["p_filesz"]
            segments.append(s)
        sections = []
        for sec in elffile.iter_sections():
            s = dict(sec.header)
            s["x_name"] = sec.name
            s["x_addr_mem_end"] = s["x_addr_file_end"] = s["sh_addr"] + s["sh_size"]
            sections.append(s)
        return ELFInfo(header, sections, segments)


@pwndbg.lib.cache.cache_until("objfile")
def get_elf_info_rebased(filepath: str, vaddr: int) -> ELFInfo:
    """
    Parse and return ELFInfo with all virtual addresses rebased to vaddr
    """
    raw_info = get_elf_info(filepath)
    # silently ignores "wrong" vaddr supplied for non-PIE ELF
    load = vaddr if raw_info.is_pic else 0
    headers = dict(raw_info.header)
    headers["e_entry"] += load  # type: ignore[operator]

    segments: List[Dict[str, int | str]] = []
    for seg in raw_info.segments:
        s = dict(seg)
        for vaddr_attr in ["p_vaddr", "x_vaddr_mem_end", "x_vaddr_file_end"]:
            s[vaddr_attr] += load  # type: ignore[operator]
        segments.append(s)

    sections: List[Dict[str, int | str]] = []
    for sec in raw_info.sections:
        s = dict(sec)
        for vaddr_attr in ["sh_addr", "x_addr_mem_end", "x_addr_file_end"]:
            s[vaddr_attr] += load  # type: ignore[operator]
        sections.append(s)

    return ELFInfo(headers, sections, segments)


def get_containing_segments(elf_filepath: str, elf_loadaddr: int, vaddr: int):
    elf = get_elf_info_rebased(elf_filepath, elf_loadaddr)
    segments = []
    for seg in elf.segments:
        # disregard segments which were unable to be named by pyelftools (see #777)
        # and non-LOAD segments that are not file-backed (typically STACK)
        if isinstance(seg["p_type"], int) or ("LOAD" not in seg["p_type"] and seg["p_filesz"] == 0):
            continue
        # disregard segments not containing vaddr
        if vaddr < seg["p_vaddr"] or vaddr >= seg["x_vaddr_mem_end"]:  # type: ignore[operator]
            continue
        segments.append(dict(seg))
    return segments


def get_containing_sections(elf_filepath: str, elf_loadaddr: int, vaddr: int):
    elf = get_elf_info_rebased(elf_filepath, elf_loadaddr)
    sections = []
    for sec in elf.sections:
        # disregard sections not occupying memory
        if sec["sh_flags"] & SH_FLAGS.SHF_ALLOC == 0:
            continue
        # disregard sections that do not contain vaddr
        if vaddr < sec["sh_addr"] or vaddr >= sec["x_addr_mem_end"]:  # type: ignore[operator]
            continue
        sections.append(dict(sec))
    return sections


def dump_section_by_name(
    filepath: str, section_name: str, try_local_path: bool = False
) -> Tuple[int, int, bytes] | None:
    """
    Dump the content of a section from an ELF file, return the start address, size and content.
    """
    # TODO: We should have some cache mechanism or something at `pndbg.aglib.file.get_file()` in the future to avoid downloading the same file multiple times when we are debugging a remote process
    local_path = pwndbg.aglib.file.get_file(filepath, try_local_path=try_local_path)

    with open(local_path, "rb") as f:
        elffile = ELFFile(f)
        section = elffile.get_section_by_name(section_name)
        return (section["sh_addr"], section["sh_size"], section.data()) if section else None


def dump_relocations_by_section_name(
    filepath: str, section_name: str, try_local_path: bool = False
) -> Tuple[Relocation, ...] | None:
    """
    Dump the relocation entries of a section from an ELF file, return a generator of Relocation objects.
    """
    # TODO: We should have some cache mechanism or something at `pndbg.aglib.file.get_file()` in the future to avoid downloading the same file multiple times when we are debugging a remote process
    local_path = pwndbg.aglib.file.get_file(filepath, try_local_path=try_local_path)

    with open(local_path, "rb") as f:
        elffile = ELFFile(f)
        section = elffile.get_section_by_name(section_name)
        if section is None or not isinstance(section, RelocationSection):
            return None
        return tuple(section.iter_relocations())


@pwndbg.aglib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def exe() -> Ehdr | None:
    """
    Return a loaded ELF header object pointing to the Ehdr of the
    main executable.
    """
    e = entry()
    if e:
        return load(e)
    return None


@pwndbg.aglib.proc.OnlyWhenRunning
@pwndbg.lib.cache.cache_until("start", "objfile")
def entry() -> int:
    """
    Return the address of the entry point for the main executable.
    """
    entry = pwndbg.auxv.get().AT_ENTRY
    if entry:
        return entry

    inf = pwndbg.dbg.selected_inferior()
    entry = inf.main_module_entry()
    if entry:
        return entry

    # Try common names
    for name in ["_start", "start", "__start", "main"]:
        try:
            return pwndbg.aglib.symbol.lookup_symbol_addr(name) or 0
        except pwndbg.dbg_mod.Error:
            pass

    # Can't find it, give up.
    return 0


def load(pointer: int) -> Ehdr | None:
    return get_ehdr(pointer)[1]


ehdr_type_loaded = 0


@pwndbg.lib.cache.cache_until("start", "objfile")
def reset_ehdr_type_loaded() -> None:
    global ehdr_type_loaded
    ehdr_type_loaded = 0


def get_ehdr(pointer: int) -> Tuple[int | None, Ehdr | None]:
    """
    Returns an ehdr object for the ELF pointer points into.

    We expect the `pointer` to be an address from the binary.
    """

    base = None

    if pwndbg.aglib.qemu.is_qemu():
        # Only check if the beginning of the page contains the ELF magic,
        # since we cannot get the memory map in qemu-user.
        page_start = pwndbg.lib.memory.page_align(pointer)
        if pwndbg.aglib.memory.read(page_start, 4, partial=True) == b"\x7fELF":
            base = page_start
        else:
            return None, None
    else:
        vmmap = pwndbg.aglib.vmmap.find(pointer)

        # If there is no vmmap for the requested address, we can't do much
        # (e.g. it could have been unmapped for whatever reason)
        if vmmap is None:
            return None, None

        # We first check if the beginning of the page contains the ELF magic
        if pwndbg.aglib.memory.read(vmmap.start, 4, partial=True) == b"\x7fELF":
            base = vmmap.start

        # The page did not have ELF magic; it may be that .text and binary start are split
        # into two pages, so let's get the first page from the pointer's page objfile
        else:
            for v in pwndbg.aglib.vmmap.get():
                if v.objfile == vmmap.objfile:
                    vmmap = v
                    break

            if pwndbg.aglib.memory.read(vmmap.start, 4, partial=True) == b"\x7fELF":
                base = vmmap.start

    if base is None:
        # For non linux ABI, the ELF header may not exist at all
        if pwndbg.dbg.selected_inferior().is_linux():
            print("ERROR: Could not find ELF base!")
        return None, None

    # Determine whether it's 32- or 64-bit
    ei_class = pwndbg.aglib.memory.byte(base + 4)

    # Find out where the section headers start
    Elfhdr: Elf32_Ehdr | Elf64_Ehdr | None = read(Ehdr, base)  # type: ignore[type-var]
    return ei_class, Elfhdr


def get_phdrs(pointer: int):
    """
    Returns a tuple containing (phnum, phentsize, gdb.Value),
    where the gdb.Value object is an ELF Program Header with
    the architecture-appropriate structure type.
    """
    _, Elfhdr = get_ehdr(pointer)

    if Elfhdr is None:
        return (0, 0, None)

    phnum = Elfhdr.e_phnum
    phoff = Elfhdr.e_phoff
    phentsize = Elfhdr.e_phentsize

    x = (phnum, phentsize, read(Phdr, Elfhdr.address + phoff))  # type: ignore[type-var]
    return x


def iter_phdrs(ehdr: Ehdr):
    if not ehdr:
        return

    phnum, phentsize, phdr = get_phdrs(ehdr.address)

    if not phdr:
        return

    first_phdr = phdr.address
    PhdrType = phdr.type

    for i in range(0, phnum):
        p_phdr = int(first_phdr + (i * phentsize))
        p_phdr = read(PhdrType, p_phdr)
        yield p_phdr


def map(pointer: int, objfile: str = "") -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Given a pointer into an ELF module, return a list of all loaded
    sections in the ELF.

    Returns:
        A sorted list of pwndbg.lib.memory.Page objects

    Example:

        >>> pwndbg.aglib.elf.load(pwndbg.aglib.regs.pc)
        [Page('400000-4ef000 r-xp 0'),
         Page('6ef000-6f0000 r--p ef000'),
         Page('6f0000-6ff000 rw-p f0000')]
        >>> pwndbg.aglib.elf.load(0x7ffff77a2000)
        [Page('7ffff75e7000-7ffff77a2000 r-xp 0x1bb000 0'),
         Page('7ffff77a2000-7ffff79a2000 ---p 0x200000 1bb000'),
         Page('7ffff79a2000-7ffff79a6000 r--p 0x4000 1bb000'),
         Page('7ffff79a6000-7ffff79ad000 rw-p 0x7000 1bf000')]
    """
    ei_class, ehdr = get_ehdr(pointer)
    return map_inner(ei_class, ehdr, objfile)


def map_inner(ei_class: int, ehdr: Ehdr, objfile: str) -> Tuple[pwndbg.lib.memory.Page, ...]:
    if not ehdr:
        return ()

    base = int(ehdr.address)

    # For each Program Header which would load data into our
    # address space, create a representation of each individual
    # page and its permissions.
    #
    # Entries are processed in-order so that later entries
    # which change page permissions (e.g. PT_GNU_RELRO) will
    # override their small subset of address space.
    pages: List[pwndbg.lib.memory.Page] = []
    for phdr in iter_phdrs(ehdr):
        memsz = int(phdr.p_memsz)

        if not memsz:
            continue

        vaddr = int(phdr.p_vaddr)
        offset = int(phdr.p_offset)
        flags = int(phdr.p_flags)

        memsz += pwndbg.lib.memory.page_offset(vaddr)
        memsz = pwndbg.lib.memory.page_size_align(memsz)
        vaddr = pwndbg.lib.memory.page_align(vaddr)
        offset = pwndbg.lib.memory.page_align(offset)

        # For each page described by this program header
        for page_addr in range(vaddr, vaddr + memsz, pwndbg.lib.memory.PAGE_SIZE):
            if page_addr in pages:
                page = pages[pages.index(page_addr)]  # type: ignore[arg-type]

                # Don't ever remove the execute flag.
                # Sometimes we'll load a read-only area into .text
                # and the loader doesn't actually *remove* the executable flag.
                if page.flags & PF_X:
                    flags |= PF_X
                page.flags = flags
            else:
                page = pwndbg.lib.memory.Page(
                    page_addr, pwndbg.lib.memory.PAGE_SIZE, flags, offset + (page_addr - vaddr)
                )
                pages.append(page)

    # Adjust against the base address that we discovered
    # for binaries that are relocatable / type DYN.
    if ET_DYN == int(ehdr.e_type):
        for page in pages:
            page.vaddr += base

    # Merge contiguous sections of memory together
    pages.sort()
    prev = pages[0]
    for page in list(pages[1:]):
        if (prev.flags & PF_W) == (page.flags & PF_W) and prev.vaddr + prev.memsz == page.vaddr:
            prev.memsz += page.memsz
            pages.remove(page)
        else:
            prev = page

    # Fill in any gaps with no-access pages.
    # This is what the linker does, and what all the '---p' pages are.
    gaps: List[pwndbg.lib.memory.Page] = []
    for i in range(len(pages) - 1):
        a, b = pages[i : i + 2]
        a_end = a.vaddr + a.memsz
        b_begin = b.vaddr
        if a_end != b_begin:
            gaps.append(pwndbg.lib.memory.Page(a_end, b_begin - a_end, 0, b.offset))

    pages.extend(gaps)

    for page in pages:
        page.objfile = objfile

    return tuple(sorted(pages))
