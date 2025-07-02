from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.paging
import pwndbg.aglib.regs
import pwndbg.color as C
import pwndbg.color.message as M
from pwndbg.commands import CommandCategory
from pwndbg.lib.regs import BitFlags

parser = argparse.ArgumentParser(description="Performs pagewalk.")
parser.add_argument("vaddr", type=str, help="virtual address to walk")
parser.add_argument("--pgd", dest="entry", type=str, default=None, help="")


pageflags = BitFlags([("NX", 63), ("PS", 7), ("A", 5), ("W", 1), ("P", 0)])


def print_pagetable_entry(name: str, paddr: int | None, vaddr: int):
    flags = ""
    arrow_right = pwndbg.chain.c.arrow(f"{pwndbg.chain.config_arrow_right}")
    if paddr is not None:
        flags = f"{arrow_right} {name + 'e'}: {C.context.format_flags(paddr, pageflags, paddr)}"
    print(f"{C.blue(name)} @ {C.yellow(hex(vaddr))} {flags}")


def pg_indices(vaddr, nr_level):
    result = [vaddr & (0x1000 - 1)]
    vaddr >>= 12
    for _ in range(nr_level):
        result.append(vaddr & (0x1FF))
        vaddr >>= 9
    return result


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.aglib.proc.OnlyWithArch(["x86-64"])
def pagewalk(vaddr, entry=None):
    vaddr = int(pwndbg.dbg.selected_frame().evaluate_expression(vaddr))
    # https://blog.zolutal.io/understanding-paging/
    level = pwndbg.aglib.kernel.arch_paginginfo().paging_level
    names = (
        "Page",
        "PT",
        "PMD",
        "PUD",
        "PGD",
    )
    if level == 5:
        names = (
            "Page",
            "PT",
            "PMD",
            "P4D",
            "PUD",
            "PGD",
        )
    entries = pwndbg.aglib.kernel.paging.pagewalk(vaddr, entry)
    for i in range(level, 0, -1):
        entry, vaddr = entries[i]
        if entry is None:
            break
        print_pagetable_entry(names[i], entry, vaddr)
    _, vaddr = entries[0]
    if vaddr is None:
        print(M.warn("address is not mapped"))
        return
    phys = vaddr - pwndbg.aglib.kernel.arch_paginginfo().physmap
    print(f"pagewalk result: {C.green(hex(vaddr))} [phys: {C.yellow(hex(phys))}]")


def paging_print_helper(name, addr):
    print(f"{C.green(name)}: {C.yellow(hex(pwndbg.aglib.kernel.phys_to_virt(int(addr))))}")


p2v_parser = argparse.ArgumentParser(
    description="Translate physical address to its corresponding virtual address."
)
p2v_parser.add_argument("paddr", type=str, help="")


@pwndbg.commands.Command(p2v_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def p2v(paddr):
    paddr = pwndbg.dbg.selected_frame().evaluate_expression(paddr)
    vaddr = pwndbg.aglib.kernel.phys_to_virt(int(paddr))
    paging_print_helper("Virtual address", vaddr)


v2p_parser = argparse.ArgumentParser(
    description="Translate virtual address to its corresponding physical address."
)
v2p_parser.add_argument("vaddr", type=str, help="")


@pwndbg.commands.Command(v2p_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def v2p(vaddr):
    vaddr = pwndbg.dbg.selected_frame().evaluate_expression(vaddr)
    paddr = pwndbg.aglib.kernel.virt_to_phys(int(vaddr))
    paging_print_helper("Physical address", paddr)
