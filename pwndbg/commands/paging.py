from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.paging
import pwndbg.aglib.regs
import pwndbg.color as C
import pwndbg.color.message as M
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


def print_pagetable_entry(name: str, paddr: int | None, vaddr: int, level: int, is_last: bool):
    pageflags = pwndbg.aglib.kernel.arch_paginginfo().pageentry_flags(is_last)
    flags = ""
    arrow_right = pwndbg.chain.c.arrow(f"{pwndbg.chain.config_arrow_right}")
    if paddr is not None:
        flags = f"{arrow_right} {name + 'e'}: {C.context.format_flags(paddr, pageflags, paddr)}"
    print(f"{C.blue(name)} @ {C.yellow(hex(vaddr))} {flags}")


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
    vaddr = int(pwndbg.dbg.selected_frame().evaluate_expression(vaddr))
    names, entries = pwndbg.aglib.kernel.pagewalk(vaddr, entry)
    for i in range(len(names) - 1, 0, -1):
        entry, vaddr = entries[i]
        next, _ = entries[i - 1]
        if entry is None:
            break
        print_pagetable_entry(names[i], entry, vaddr, i, next is None or i == 1)
    _, vaddr = entries[0]
    if vaddr is None:
        print(M.warn("address is not mapped"))
        return
    phys = vaddr - pwndbg.aglib.kernel.arch_paginginfo().physmap
    print(f"pagewalk result: {C.green(hex(vaddr))} [phys: {C.yellow(hex(phys))}]")


def paging_print_helper(name, addr):
    print(f"{C.green(name)}: {C.yellow(hex(addr))}")


p2v_parser = argparse.ArgumentParser(
    description="Translate physical address to its corresponding virtual address."
)
p2v_parser.add_argument("paddr", type=str, help="")


@pwndbg.commands.Command(p2v_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def p2v(paddr):
    paddr = int(pwndbg.dbg.selected_frame().evaluate_expression(paddr))
    vaddr = pwndbg.aglib.kernel.phys_to_virt(paddr)
    paging_print_helper("Virtual address", vaddr)
    page = pwndbg.aglib.kernel.virt_to_page(vaddr)
    page_info(page)


v2p_parser = argparse.ArgumentParser(
    description="Translate virtual address to its corresponding physmap address."
)
v2p_parser.add_argument("vaddr", type=str, help="")


@pwndbg.commands.Command(v2p_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def v2p(vaddr):
    vaddr = int(pwndbg.dbg.selected_frame().evaluate_expression(vaddr))
    entry, paddr = pwndbg.aglib.kernel.pagewalk(vaddr)[1][0]  # more accurate
    if not entry:
        print(M.warn("virtual to page failed"))
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
@pwndbg.commands.OnlyWithKernelDebugSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "aarch64"])
def pageinfo(page):
    page = int(pwndbg.dbg.selected_frame().evaluate_expression(page))
    vaddr = pwndbg.aglib.kernel.page_to_virt(page)
    paging_print_helper("Virtual address", vaddr)
    page_info(page)
