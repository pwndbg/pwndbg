from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
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


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL, archs=["x86-64"])
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def pagewalk(vaddr, entry=None):
    vaddr = int(pwndbg.dbg.selected_frame().evaluate_expression(vaddr))
    # https://blog.zolutal.io/understanding-paging/
    base = pwndbg.aglib.kernel.physmap_base()
    level = 4
    names = (
        "Page",
        "PT",
        "PMD",
        "PUD",
        "PGD",
    )
    if pwndbg.aglib.kernel.uses_5lvl_paging():
        level = 5
        names = (
            "Page",
            "PT",
            "PMD",
            "P4D",
            "PUD",
            "PGD",
        )
    if entry is None:
        entry = pwndbg.aglib.regs["cr3"]
    else:
        entry = int(pwndbg.dbg.selected_frame().evaluate_expression(entry))
    if entry > base:
        # user inputted a physmap address as pointer to pgd
        entry -= base
    offset = 0
    entry_mask = ~((1 << 12) - 1) & ((1 << 51) - 1)
    for i in range(level, 0, -1):
        cur = (entry & entry_mask) + base
        if entry & (1 << 7) > 0:
            break
        shift = (i - 1) * 9 + 12
        offset = vaddr & ((1 << shift) - 1)
        idx = (vaddr & (0x1FF << shift)) >> shift
        entry = 0
        try:
            table = pwndbg.aglib.memory.get_typed_pointer("unsigned long", cur)
            entry = int(table[idx])
            print_pagetable_entry(names[i], entry, cur)
        except Exception as e:
            print(M.warn(f"Exception while page walking: {e}"))
            entry = 0
        if entry == 0:
            print(M.warn("address is not mapped"))
            return
    virtual = base + (entry & entry_mask) + offset
    print(f"pagewalk result: {C.green(hex(virtual))} [phys: {C.yellow(hex(virtual - base))}]")


p2v_parser = argparse.ArgumentParser(
    description="Translate physical address to its corresponding virtual address."
)
p2v_parser.add_argument("paddr", type=str, help="")


@pwndbg.commands.Command(p2v_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def p2v(paddr):
    paddr = pwndbg.dbg.selected_frame().evaluate_expression(paddr)
    return pwndbg.aglib.kernel.phys_to_virt(int(paddr))


v2p_parser = argparse.ArgumentParser(
    description="Translate virtual address to its corresponding physical address."
)
v2p_parser.add_argument("vaddr", type=str, help="")


@pwndbg.commands.Command(v2p_parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def v2p(vaddr):
    vaddr = pwndbg.dbg.selected_frame().evaluate_expression(vaddr)
    return pwndbg.aglib.kernel.virt_to_phys(int(vaddr))
