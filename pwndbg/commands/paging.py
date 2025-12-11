from __future__ import annotations

import argparse
import math

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.paging
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.chain
import pwndbg.color as C
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.aglib.kernel.paging import PageTableLevel
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


def print_pagetable_entry(ptl: PageTableLevel, level: int, is_last: bool):
    pageflags = pwndbg.aglib.kernel.arch_paginginfo().pageentry_flags(is_last)
    flags = ""
    arrow_right = pwndbg.chain.c.arrow(f"{pwndbg.chain.config_arrow_right}")
    name, entry, vaddr, idx = ptl.name, ptl.entry, ptl.virt, ptl.idx
    if pwndbg.aglib.arch.name == "x86-64":
        name = name.ljust(3, " ")
    nbits = pwndbg.aglib.kernel.arch_ops().page_shift - math.ceil(
        math.log2(pwndbg.aglib.arch.ptrsize)
    )  # each idx has that many bits
    idxlen = len(str((1 << nbits) - 1))
    if entry is not None:
        flags = f"[{idx:0{idxlen}}] {arrow_right} {name + 'e'}: {C.context.format_flags(entry, pageflags, entry)}"
    print(f"{C.blue(name)} @ {C.yellow(hex(vaddr))}{flags}")


def page_type(page):
    names = PAGETYPES
    page_type_val = pwndbg.aglib.memory.s32(page + 0x30)
    if page_type_val == -1:
        return "initialized"
    if page_type_val >= 0:
        return f"mapcount: {page_type_val}"
    page_type_val = pwndbg.aglib.memory.u32(page + 0x30)
    if pwndbg.aglib.kernel.krelease() >= (6, 12):
        idx = (page_type_val >> 24) - 0xF0
        if idx < len(names):
            return names[idx]
    if pwndbg.aglib.kernel.krelease() >= (6, 11):
        names = names[:-1][::-1]
        for i in range(len(names)):
            if page_type_val & (1 << (i + 24)) == 0:
                return names[i]
    if pwndbg.aglib.kernel.krelease() >= (6, 10):
        names = names[:6]
        for i in range(len(names)):
            if page_type_val & (1 << (7 + i)) == 0:
                return names[i]
    if pwndbg.aglib.kernel.krelease() >= (5, 0):
        names = names[:5]
        for i in range(len(names)):
            if page_type_val & (1 << (7 + i)) == 0:
                return names[i]
    return "unknown"


def page_info(page):
    try:
        refcount = pwndbg.aglib.memory.u32(page + 0x34)
        print(
            f"{C.green('page')} @ {C.yellow(hex(page))} [{page_type(page)}, refcount: {refcount}]"
        )
    except (ValueError, TypeError):
        print(M.warn("invalid page address"))


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def pagewalk(vaddr, entry=None):
    if entry is not None:
        entry = int(pwndbg.dbg.selected_frame().evaluate_expression(entry))
    else:
        # did the user set pgd with kcurrent?
        # safe because pagewalk fallbacks to control regs when entry==None
        entry = pwndbg.commands.kcurrent.KCURRENT_PGD
    vaddr = int(pwndbg.dbg.selected_frame().evaluate_expression(vaddr))
    levels = pwndbg.aglib.kernel.pagewalk(vaddr, entry)
    for i in range(len(levels) - 1, 0, -1):
        curr = levels[i]
        next = levels[i - 1]
        if curr.entry is None:
            break
        print_pagetable_entry(curr, i, next.entry is None or i == 1)
    vaddr = levels[0].virt
    if vaddr is None:
        print(M.warn("address is not mapped"))
        return
    pi = pwndbg.aglib.kernel.arch_paginginfo()
    phys = vaddr - pi.physmap + pi.phys_offset
    print(f"pagewalk result: {C.green(hex(vaddr))} [phys: {C.yellow(hex(phys))}]")


def paging_print_helper(name, addr):
    if addr is None:
        return
    print(f"{C.green(name)}: {C.yellow(hex(addr))}")


p2v_parser = argparse.ArgumentParser(
    description="Translate physical address to its corresponding virtual address."
)
p2v_parser.add_argument("paddr", type=str, help="")


@pwndbg.commands.Command(p2v_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def p2v(paddr):
    paddr = int(pwndbg.dbg.selected_frame().evaluate_expression(paddr))
    try:
        vaddr = pwndbg.aglib.kernel.phys_to_virt(paddr)
        paging_print_helper("Virtual address", vaddr)
        page = pwndbg.aglib.kernel.virt_to_page(vaddr)
        page_info(page)
    except Exception:
        print(M.warn("physical to virtual address failed, invalid physical address?"))


v2p_parser = argparse.ArgumentParser(
    description="Translate virtual address to its corresponding physmap address."
)
v2p_parser.add_argument("vaddr", type=str, help="")


@pwndbg.commands.Command(v2p_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def v2p(vaddr):
    vaddr = int(pwndbg.dbg.selected_frame().evaluate_expression(vaddr))
    level = pwndbg.aglib.kernel.pagewalk(vaddr)[0]  # more accurate
    entry, paddr = level.entry, level.virt
    if not entry:
        print(M.warn("virtual to physical address failed, unmapped virtual address?"))
        return
    paging_print_helper("Physmap address", paddr)
    # paddr is the physmap address which is a virtual address
    page = pwndbg.aglib.kernel.virt_to_page(paddr)
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
def pageinfo(page):
    page = int(pwndbg.dbg.selected_frame().evaluate_expression(page))
    try:
        vaddr = pwndbg.aglib.kernel.page_to_virt(page)
        paging_print_helper("Virtual address", vaddr)
        page_info(page)
    except Exception:
        print(M.warn("invalid page struct pointer"))
