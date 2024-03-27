# Some of the code here was inspired from https://github.com/osandov/drgn/

from typing import Dict
from typing import Generator
from typing import Union

import gdb

import pwndbg


class KernelLog:
    def __init__(self) -> None:
        self._prb = gdb.lookup_symbol("prb")[0].value()

    def get_logs(self) -> Generator[Dict[str, Union[int, str]], None, None]:
        # TODO/FIXME: currently only working for linux >= 5.10 (commit 896fbe20b4e2)
        descriptor_ring = self._prb["desc_ring"]
        descriptors = descriptor_ring["descs"]
        infos = descriptor_ring["infos"]

        tail_id = int(descriptor_ring["tail_id"]["counter"])
        head_id = int(descriptor_ring["head_id"]["counter"])

        ring_count_mask = 1 << int(descriptor_ring["count_bits"])
        ring_data_size_mask = 1 << int(self._prb["text_data_ring"]["size_bits"])

        text_data_start = int(self._prb["text_data_ring"]["data"])

        for descriptor_id in range(tail_id, head_id + 1):
            descriptor_id %= ring_count_mask
            descriptor = descriptors[descriptor_id]

            state_var = 3 & (
                int(descriptor["state_var"]["counter"]) >> (pwndbg.gdblib.arch.ptrsize * 8 - 2)
            )
            if state_var not in [1, 2]:
                # Skip non-committed record
                continue

            info = infos[descriptor_id]
            text_length = int(info["text_len"])

            if text_length == 0:
                # Skip data-less record
                continue

            # TODO: handle wrapping data block

            text_start = (
                text_data_start + int(descriptor["text_blk_lpos"]["begin"]) % ring_data_size_mask
            )
            # skip over descriptor id
            text_start += pwndbg.gdblib.arch.ptrsize

            text_data = pwndbg.gdblib.memory.read(text_start, text_length)

            text = text_data.decode(encoding="utf8", errors="replace")
            timestamp = int(info["ts_nsec"])  # timestamp in nanoseconds
            log_level = int(info["level"])  # syslog level
            facility = int(info["facility"])

            yield {
                "timestamp": timestamp,
                "text": text,
                "log_level": log_level,
                "facility": facility,
            }
