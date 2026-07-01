from __future__ import annotations

import argparse
import math

import pwndbg.aglib
import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.chain
import pwndbg.color.context as ctx_color
import pwndbg.commands
import pwndbg.commands.kcurrent
from pwndbg import color
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Performs pagewalk.")
parser.add_argument("vaddr", type=str, help="virtual address to walk")
parser.add_argument("--pgd", dest="entry", type=str, default=None, help="")

PAGETYPES = (
    "buddy",
    "offline",
    "table",
    "guard",
    "hugetlb",
    "slab",
    "zsmalloc",
    "unaccepted",
)


def page_type(page) -> str:
    names = PAGETYPES
    page_type_val = pwndbg.aglib.memory.s32(page + 0x30)
    if page_type_val == -1:
        return "initialized"
    if page_type_val >= 0:
        return f"mapcount: {page_type_val}"
    page_type_val = pwndbg.aglib.memory.u32(page + 0x30)
    krelease = pwndbg.aglib.kernel.krelease()
    if not krelease or krelease >= (6, 12):
        idx = (page_type_val >> 24) - 0xF0
        if idx < len(names):
            return names[idx]
    elif krelease >= (6, 11):
        names = names[:-1][::-1]
        for i in range(len(names)):
            if page_type_val & (1 << (i + 24)) == 0:
                return names[i]
    elif krelease >= (6, 10):
        names = names[:6]
        for i in range(len(names)):
            if page_type_val & (1 << (7 + i)) == 0:
                return names[i]
    elif krelease >= (5, 0):
        names = names[:5]
        for i in range(len(names)):
            if page_type_val & (1 << (7 + i)) == 0:
                return names[i]
    return "unknown"


def page_info(page) -> None:
    try:
        refcount = pwndbg.aglib.memory.u32(page + 0x34)
        print(
            f"{color.green('page')} @ {color.yellow(hex(page))} [{page_type(page)}, refcount: {refcount}]"
        )
    except (ValueError, TypeError):
        print(message.warn("invalid page address"))


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def pagewalk(vaddr, entry=None) -> None:
    if entry is not None:
        entry = int(pwndbg.dbg.selected_frame().evaluate_expression(entry))
    elif (kcurrent := pwndbg.commands.kcurrent.get_kcurrent()) is not None:
        # did the user set pgd with kcurrent?
        # safe because pagewalk fallbacks to control regs when entry==None
        entry = kcurrent.pgd
    if pwndbg.aglib.memory.is_kernel(entry):
        entry = pwndbg.aglib.kernel.pagewalk(entry, virt=False).phys
    vaddr = int(pwndbg.dbg.selected_frame().evaluate_expression(vaddr))
    result = pwndbg.aglib.kernel.pagewalk(vaddr, entry)
    for level in result.levels[::-1]:
        name, entry, vaddr, idx = level.name, level.entry, level.virt, level.idx
        if name is None or entry is None or vaddr is None or idx is None:
            break
        pageflags = pwndbg.aglib.kernel.bitflags(level)
        flags = ""
        arrow_right = pwndbg.chain.c.arrow(f"{pwndbg.chain.config_arrow_right}")
        if pwndbg.aglib.arch.name == "x86-64":
            name = name.ljust(3, " ")
        nbits = pwndbg.aglib.kernel.page_shift() - math.ceil(
            math.log2(pwndbg.aglib.arch.ptrsize)
        )  # each idx has that many bits
        idxlen = len(str((1 << nbits) - 1))
        if entry is not None:
            flags = f"[{idx:0{idxlen}}] {arrow_right} {name + 'e'}: {ctx_color.format_flags(entry, pageflags, entry)}"
        print(f"{color.blue(name)} @ {color.yellow(hex(vaddr))}{flags}")
    vaddr = result.virt
    if vaddr is None:
        print(message.warn("address is not mapped"))
        return
    phys = result.phys
    if phys:
        phys = color.yellow(hex(phys))
    print(f"pagewalk result: {color.green(hex(vaddr))} [phys: {phys}]")


def paging_print_helper(name, addr):
    if addr is None:
        return
    print(f"{color.green(name)}: {color.yellow(hex(addr))}")


p2v_parser = argparse.ArgumentParser(
    description="Translate physical address to its corresponding virtual address."
)
p2v_parser.add_argument("paddr", type=str, help="")


@pwndbg.commands.Command(p2v_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def p2v(paddr) -> None:
    paddr = int(pwndbg.dbg.selected_frame().evaluate_expression(paddr))
    try:
        vaddr = pwndbg.aglib.kernel.phys_to_virt(paddr)
        paging_print_helper("Virtual address", vaddr)
        page = pwndbg.aglib.kernel.virt_to_page(vaddr)
        page_info(page)
    except Exception:
        print(message.warn("physical to virtual address failed, invalid physical address?"))


v2p_parser = argparse.ArgumentParser(
    description="Translate virtual address to its corresponding physmap address."
)
v2p_parser.add_argument("vaddr", type=str, help="")


@pwndbg.commands.Command(v2p_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def v2p(vaddr) -> None:
    vaddr = int(pwndbg.dbg.selected_frame().evaluate_expression(vaddr))
    result = pwndbg.aglib.kernel.pagewalk(vaddr)  # more accurate
    entry, paddr = result.entry, result.phys
    if not entry or paddr is None:
        print(message.warn("virtual to physical address failed, unmapped virtual address?"))
        return
    paging_print_helper("Physical address", paddr)
    # paddr is the physmap address which is a virtual address
    page = pwndbg.aglib.kernel.phys_to_page(paddr)
    page_info(page)


page_parser = argparse.ArgumentParser(
    description="Convert a pointer to a `struct page` to its corresponding virtual address."
)
page_parser.add_argument("page", type=str, help="")


@pwndbg.commands.Command(page_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def pageinfo(page) -> None:
    page = int(pwndbg.dbg.selected_frame().evaluate_expression(page))
    try:
        vaddr = pwndbg.aglib.kernel.page_to_virt(page)
        paging_print_helper("Virtual address", vaddr)
        page_info(page)
    except Exception:
        print(message.warn("invalid page struct pointer"))
