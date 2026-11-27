from __future__ import annotations

import argparse
import logging
from collections.abc import Iterator

import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.hexdump
from pwndbg import color
from pwndbg.aglib.kernel.macros import container_of
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.aglib.kernel.rbtree import for_each_rb_entry
from pwndbg.commands import CommandCategory

log = logging.getLogger(__name__)

addrc = color.green
fieldnamec = color.blue
fieldvaluec = color.yellow
typenamec = color.red

scudo_parser = argparse.ArgumentParser(description="Analyzes a Scudo allocator chunk of memory")
scudo_parser.add_argument("address", type=int, help="Variable base address")

@pwndbg.commands.Command(scudo_parser, category=CommandCategory.KERNEL)

def scudo_chunk(address: int):
    try:
        header_addr = address - 0x10
        header_val = pwndbg.aglib.memory.u64(header_addr)
        
        classid = header_val & 0xFF
        state = (header_val >> 8) & 0x3
        origin = (header_val >> 10) & 0x3
        size = (header_val >> 12) & 0xfffff
        offset = (header_val >> 32) & 0xffff
        checksum = (header_val >> 48) & 0xffff
        
        print(color.green(f"[*] Scudo Chunk at {hex(header_addr)}"))
        print(f"classId : {classid}")
        print(f"state   : {state}")
        print(f"origin  : {origin}")
        print(f"size    : {size} (0x{size:x})")
        print(f"offset  : {offset}")
        print(f"checksum: {checksum}")
        
    except Exception:
        return