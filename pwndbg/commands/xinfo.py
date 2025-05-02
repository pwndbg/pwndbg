from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.stack
import pwndbg.aglib.vmmap
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.wrappers
from pwndbg.commands import CommandCategory
from pwndbg.lib.memory import Page

parser = argparse.ArgumentParser(
    description="Shows offsets of the specified address from various useful locations."
)
parser.add_argument("address", nargs="?", default="$pc", help="Address to inspect")


def print_line(name, addr, first, second, op, width=20) -> None:
    print(
        f"{name.rjust(width)} {M.get(addr)} = {M.get(first) if not isinstance(first, str) else first.ljust(len(hex(addr).rstrip('L')))} {op} {second:#x}"
    )


def xinfo_stack(page: Page, addr: int) -> None:
    # If it's a stack address, print offsets to top and bottom of stack, as
    # well as offsets to current stack and base pointer (if used by debuggee)

    sp = pwndbg.aglib.regs.sp
    frame = pwndbg.aglib.regs[pwndbg.aglib.regs.frame]
    frame_mapping = pwndbg.aglib.vmmap.find(frame)

    print_line("Stack Top", addr, page.vaddr, addr - page.vaddr, "+")
    print_line("Stack End", addr, page.end, page.end - addr, "-")
    print_line("Stack Pointer", addr, sp, addr - sp, "+")

    if frame_mapping and page.vaddr == frame_mapping.vaddr:
        print_line("Frame Pointer", addr, frame, frame - addr, "-")

    canary_value = pwndbg.commands.canary.canary_value()[0]

    if canary_value is not None:
        all_canaries = list(
            pwndbg.search.search(
                pwndbg.aglib.arch.pack(canary_value), mappings=pwndbg.aglib.stack.get().values()
            )
        )
        follow_canaries = sorted(filter(lambda a: a > addr, all_canaries))
        if follow_canaries is not None and len(follow_canaries) > 0:
            nxt = follow_canaries[0]
            print_line("Next Stack Canary", addr, nxt, nxt - addr, "-")


def xinfo_mmap_file(page: Page, addr: int) -> None:
    # If it's an address pointing into a memory mapped file, print offsets
    # to beginning of file in memory and on disk

    file_name = page.objfile

    objpages = filter(lambda p: p.objfile == file_name, pwndbg.aglib.vmmap.get())
    first = sorted(objpages, key=lambda p: p.vaddr)[0]

    # print offset from ELF base load address
    rva = addr - first.vaddr
    print_line("File (Base)", addr, first.vaddr, rva, "+")

    # find possible LOAD segments that designate memory and file backings
    containing_loads = [
        seg
        for seg in pwndbg.aglib.elf.get_containing_segments(file_name, first.vaddr, addr)
        if seg["p_type"] == "PT_LOAD"
    ]

    for segment in containing_loads:
        if segment["p_type"] == "PT_LOAD" and addr < segment["x_vaddr_mem_end"]:
            offset = addr - segment["p_vaddr"]
            print_line("File (Segment)", addr, segment["p_vaddr"], offset, "+")
            break

    for segment in containing_loads:
        if segment["p_type"] == "PT_LOAD" and addr < segment["x_vaddr_file_end"]:
            file_offset = segment["p_offset"] + (addr - segment["p_vaddr"])
            print_line("File (Disk)", addr, file_name, file_offset, "+")
            break
    else:
        print(f"{'File (Disk)'.rjust(20)} {M.get(addr)} = [not file backed]")

    containing_sections = pwndbg.aglib.elf.get_containing_sections(file_name, first.vaddr, addr)
    if len(containing_sections) > 0:
        print("\n Containing ELF sections:")
        for sec in containing_sections:
            print_line(sec["x_name"], addr, sec["sh_addr"], addr - sec["sh_addr"], "+")


def xinfo_default(page: Page, addr: int) -> None:
    # Just print the distance to the beginning of the mapping
    print_line("Mapped Area", addr, page.vaddr, addr - page.vaddr, "+")


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def xinfo(address=None) -> None:
    address = address.cast(
        pwndbg.aglib.typeinfo.pvoid
    )  # Fixes issues with function ptrs (xinfo malloc)
    addr = int(address)
    addr &= pwndbg.aglib.arch.ptrmask

    page = pwndbg.aglib.vmmap.find(addr)

    if page is None:
        print(f"\n  Virtual address {addr:#x} is not mapped.")
        return

    print(f"Extended information for virtual address {M.get(addr)}:")

    print("\n  Containing mapping:")
    print(M.get(address, text=str(page)))

    print("\n  Offset information:")

    if page.is_stack:
        xinfo_stack(page, addr)
    else:
        xinfo_default(page, addr)

    if page.is_memory_mapped_file:
        xinfo_mmap_file(page, addr)
