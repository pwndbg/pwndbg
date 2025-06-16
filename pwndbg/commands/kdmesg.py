"""
Display the kernel ring buffer (dmesg) contents.
This command reads the `printk_ringbuffer` structure, which stores printk messages.
It iterates through the records in the ring buffer to print each record like a dmesg log.

This command supports only the "new" kernel ring buffer implementation that is present in kernel versions 5.10+.
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d594d8f411d47bf7b583ec3474b11fec348c88bb

This implementation read information from the Linux kernel's `printk_ringbuffer` structure as defined in:
https://github.com/torvalds/linux/blob/19272b37aa4f83ca52bdf9c16d5d81bdd1354494/kernel/printk/printk_ringbuffer.h
"""

from __future__ import annotations

import argparse
import time

import pwndbg.color.message as message
import pwndbg.commands

parser = argparse.ArgumentParser(description="Displays the kernel ring buffer (dmesg) contents.")

parser.add_argument("-T", "--ctime", action="store_true", help="Print human-readable timestamps.")


@pwndbg.commands.Command(
    parser,
    category=pwndbg.commands.CommandCategory.KERNEL,
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugInfo
def kdmesg(ctime: bool = False) -> None:
    prb_addr = pwndbg.aglib.symbol.lookup_symbol_addr("printk_rb_static")

    if prb_addr is None:
        print(
            "The printk_rb_static symbol was not found. This may indicate that the kernel is an older version or that the symbol is not available in the current build."
        )
        return

    try:
        # Read printk_ringbuffer structure, which contains a desc_ring and text_data_ring.
        # This struct contains metadata for accessing the ring buffer.
        printk_ringbuffer_type = pwndbg.aglib.memory.get_typed_pointer_value(
            "struct printk_ringbuffer", prb_addr
        )
        desc_ring_addr = printk_ringbuffer_type["desc_ring"].address
        text_data_ring_addr = printk_ringbuffer_type["text_data_ring"].address

        # Read prb_desc_ring structures, which contain metadata about the ring buffer descriptors.
        desc_ring_type = pwndbg.aglib.memory.get_typed_pointer_value(
            "struct prb_desc_ring", desc_ring_addr
        )
        desc_ring_count = 1 << int(desc_ring_type["count_bits"])

        # Find addresses and sizes of descs and infos, neede
        descs = int(desc_ring_type["descs"])
        infos = int(desc_ring_type["infos"])

        # Read prb_data_ring structure, calculate text data size and address.
        # This struct contains the actual text data for the printk messages.
        text_data_ring_type = pwndbg.aglib.memory.get_typed_pointer_value(
            "struct prb_data_ring", text_data_ring_addr
        )
        text_data_sz = 1 << int(text_data_ring_type["size_bits"])
        text_data_addr = int(text_data_ring_type["data"])

        size_long = pwndbg.aglib.typeinfo.lookup_types("long").sizeof
        desc_flags_shift = size_long * 8 - 2
        desc_flags_mask = 3 << desc_flags_shift
        desc_id_mask = ~desc_flags_mask

        # We wish to iterate from tail to head, so we need to find the tail_id and head_id.
        head_id = int(desc_ring_type["head_id"]["counter"])
        tail_id = int(desc_ring_type["tail_id"]["counter"])

        did = int(tail_id)

        prb_desc_size = pwndbg.aglib.typeinfo.load("struct prb_desc").sizeof
        printk_info_size = pwndbg.aglib.typeinfo.load("struct printk_info").sizeof

        # Iterate through each record from tail to head.
        while True:
            ind = did % desc_ring_count
            desc = pwndbg.aglib.memory.get_typed_pointer_value(
                "struct prb_desc", descs + prb_desc_size * ind
            )

            # Skip non-committed or non-finalized records, indicated by the state variable.
            state = 3 & (int(desc["state_var"]["counter"]) >> desc_flags_shift)
            if state != 1 and state != 2:  # desc_committed or desc_finalized
                if did == head_id:
                    break
                did = (did + 1) & desc_id_mask
                continue

            begin = int(desc["text_blk_lpos"]["begin"]) % text_data_sz
            end = int(desc["text_blk_lpos"]["next"]) % text_data_sz

            info = pwndbg.aglib.memory.get_typed_pointer_value(
                "struct printk_info", infos + printk_info_size * ind
            )

            # Read text data from the text_data_ring.
            if begin & 1 == 1:
                text = ""
            else:
                if begin > end:
                    begin = 0

                text_start = begin + size_long
                text_len = int(info["text_len"])

                if end - text_start < text_len:
                    text_len = end - text_start

                text_data = pwndbg.aglib.memory.read(text_data_addr + text_start, text_len)
                text = text_data.decode(encoding="utf8", errors="replace")

            # Format and print the message.
            if ctime:
                tk_core_addr = pwndbg.aglib.symbol.lookup_symbol_addr("tk_core")

                if tk_core_addr is None:
                    print(
                        message.error(
                            "The tk_core symbol was not found. This may indicate that the kernel is an older version or that the symbol is not available in the current build."
                        )
                    )
                    return

                if pwndbg.aglib.typeinfo.load("struct tk_data") is None:
                    print(
                        message.error(
                            "`struct tk_data` is not defined in the current debug symbols."
                        )
                    )
                    return

                tk_core = pwndbg.aglib.memory.get_typed_pointer_value(
                    "struct tk_data", tk_core_addr
                )
                epoch_time = int(tk_core["timekeeper"]["xtime_sec"])

                for line in text.splitlines():
                    print(f"[{time.ctime(int(info['ts_nsec'] ) / 1e9 + epoch_time)}] {line}")
            else:
                for line in text.splitlines():
                    print(f"[{int(info['ts_nsec']) / 1e9:12.6f}] {line}")

            if did == head_id:
                break
            did = (did + 1) & desc_id_mask

    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return
