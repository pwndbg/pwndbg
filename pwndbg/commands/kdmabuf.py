from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.dmabuf
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.commands
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib.exception import IndentContextManager

SG_CHAIN = 0x1
SG_END = 0x2

parser = argparse.ArgumentParser(description="Prints DMA buf info")


def print_dmabuf(dmabuf, idx, indent):
    size = int(dmabuf["size"])
    file = int(dmabuf["file"])
    exp_name = pwndbg.aglib.memory.string(int(dmabuf["exp_name"])).decode()
    name = int(dmabuf["name"])
    desc = indent.prefix(f"[0x{idx:02x}] DMA-buf") + f" @ {indent.addr_hex(int(dmabuf))}"
    desc += f" [size: {indent.aux_hex(size)}, file: {indent.aux_hex(file)}, exporter: {exp_name}]"
    if name != 0:
        desc += f" (name: {pwndbg.aglib.memory.string(name)})"
    indent.print(desc)


def print_sgl(sgl, indent):
    sgl_type_len = pwndbg.aglib.typeinfo.lookup_types("struct scatterlist").sizeof
    next_sgl = int(sgl)
    idx = 0
    while True:
        sgl = pwndbg.aglib.memory.get_typed_pointer("struct scatterlist", next_sgl)
        page_link = int(sgl["page_link"])
        page = page_link & ~(SG_CHAIN | SG_END)
        if page_link & SG_CHAIN:
            next_sgl = page
            continue
        virt = pwndbg.aglib.kernel.page_to_virt(page)
        phys = pwndbg.aglib.kernel.virt_to_phys(virt)
        offset = int(sgl["offset"])
        length = int(sgl["length"])
        desc = "- " + indent.prefix(f"[0x{idx:02x}] {indent.addr_hex(virt)}")
        desc += f" (len: {indent.aux_hex(length)}, off: {indent.aux_hex(offset)}) [page: {indent.aux_hex(page)}, phys: {indent.aux_hex(phys)}]"
        idx += 1
        indent.print(desc)
        if page_link & SG_END:
            break
        next_sgl += sgl_type_len
        tmp = pwndbg.aglib.memory.read_pointer_width(next_sgl)
        if not pwndbg.aglib.memory.is_kernel(tmp):
            next_sgl += pwndbg.aglib.arch.ptrsize
        tmp = pwndbg.aglib.memory.read_pointer_width(next_sgl)
        if not pwndbg.aglib.memory.is_kernel(tmp):
            break


# adapted from https://github.com/bata24/gef/tree/dev
@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
def kdmabuf() -> None:
    db_name = "db_list"
    if pwndbg.aglib.kernel.krelease() >= (6, 10):
        db_name = "debugfs_list"
        if "CONFIG_DEBUG_FS" not in pwndbg.aglib.kernel.kconfig():
            print(message.warn("dma_buf->priv does not exist"))
    db_list = pwndbg.aglib.kernel.db_list()
    if db_list is None:
        print(message.warn(f"{db_name} not found"))
        return
    db_list = pwndbg.aglib.memory.get_typed_pointer("struct list_head", db_list)
    if int(db_list) == int(db_list["next"]):
        print(message.warn(f"{db_name} ({hex(int(db_list))}) is empty"))
        return
    indent = IndentContextManager()
    pwndbg.aglib.kernel.dmabuf.recover_dmabuf_typeinfo(int(db_list["next"]))
    for idx, e in enumerate(for_each_entry(db_list.dereference(), "struct dma_buf", "list_node")):
        print_dmabuf(e, idx, indent)
        priv = e["priv"]
        if not pwndbg.aglib.memory.is_kernel(int(priv)):
            indent.print(message.warn("(no entries)"))
            continue
        nents = int(priv["sg_table"]["nents"])
        if nents == 0:
            indent.print(message.warn("(no entries)"))
            continue
        with indent:
            desc = indent.prefix("system_heap_buffer")
            desc += f" @ {indent.addr_hex(int(priv))} [nents: {indent.aux_hex(nents)}]"
            indent.print(desc)
            print_sgl(priv["sg_table"]["sgl"], indent)
