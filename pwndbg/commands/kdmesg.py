import pwndbg.commands
import pwndbg.color.message as message

@pwndbg.commands.Command(
    "Displays the kernel ring buffer (dmesg) contents.", 
    category=pwndbg.commands.CommandCategory.KERNEL
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugSyms
def kdmesg() -> None:
    prb_addr = pwndbg.aglib.symbol.lookup_symbol_addr("printk_rb_static")

    if prb_addr is None:
        print("The printk_rb_static symbol was not found. This may indicate that the kernel is an older version or that the symbol is not available in the current build.")
        return

    try:
        printk_ringbuffer_type = pwndbg.aglib.memory.get_typed_pointer_value("struct printk_ringbuffer", prb_addr)
        desc_ring_addr = printk_ringbuffer_type["desc_ring"].address
        text_data_ring_addr = printk_ringbuffer_type["text_data_ring"].address

        desc_ring_type = pwndbg.aglib.memory.get_typed_pointer_value("struct prb_desc_ring", desc_ring_addr)
        desc_ring_count = 1 << int(desc_ring_type["count_bits"])
        descs = int(desc_ring_type["descs"])
        infos = int(desc_ring_type["infos"])

        text_data_ring_type = pwndbg.aglib.memory.get_typed_pointer_value("struct prb_data_ring", text_data_ring_addr)
        text_data_sz = 1 << int(text_data_ring_type["size_bits"])
        text_data_addr = text_data_ring_type["data"]

        size_long = pwndbg.aglib.typeinfo.lookup_types("long").sizeof
        desc_flags_shift = size_long * 8 - 2
        desc_flags_mask = 3 << desc_flags_shift
        desc_id_mask = ~desc_flags_mask

        head_id = int(desc_ring_type["head_id"]["counter"])
        tail_id = int(desc_ring_type["tail_id"]["counter"])

        did = int(tail_id)

        prb_desc_size = pwndbg.aglib.typeinfo.load("struct prb_desc").sizeof
        printk_info_size = pwndbg.aglib.typeinfo.load("struct printk_info").sizeof

        while True:
            ind = did % desc_ring_count

            desc_off = prb_desc_size * ind
            info_off = printk_info_size * ind

            desc_addr = descs + desc_off
            info_addr = infos + info_off

            desc = pwndbg.aglib.memory.get_typed_pointer_value("struct prb_desc", desc_addr)
            
            state = 3 & (int(desc["state_var"]["counter"]) >> desc_flags_shift)
            if state != 1 and state != 2: # desc_committed or desc_finalized
                if did == head_id:
                    break
                did = (did + 1) & desc_id_mask
                continue

            begin = int(desc["text_blk_lpos"]["begin"]) % text_data_sz
            end = int(desc["text_blk_lpos"]["next"]) % text_data_sz

            info = pwndbg.aglib.memory.get_typed_pointer_value("struct printk_info", info_addr)

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
                text = text_data.decode(encoding='utf8', errors='replace')

            time_stamp = int(info["ts_nsec"])

            for line in text.splitlines():
                print(f"[{time_stamp / 1000000000:12.6f}] {line}")

            if did == head_id:
                break
            did = (did + 1) & desc_id_mask

    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return