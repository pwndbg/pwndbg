from __future__ import annotations

import re
import string
from struct import unpack_from

from pwnlib.util.packing import p16
from pwnlib.util.packing import u32
from pwnlib.util.packing import u64

import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.gdblib.kernel
import pwndbg.lib.cache
import pwndbg.search


@pwndbg.lib.cache.cache_until("start")
def get_ks():
    ks = Kallsyms()
    return ks.kallsyms


class Kallsyms:
    """
    CONFIG_KALLSYMS_BASE_RELATIVE=y

    - linux_banner >= 6.4
    - ... <= 6.4
    - kallsyms_offsets
    - kallsyms_relative_base
    - kallsyms_num_syms
    - kallsyms_names
    - kallsyms_markers
    - kallsyms_token_table
    - kallsyms_token_index
    - kallsyms_offsets >= 6.4
    - kallsyms_relative_base >= 6.4
    """

    def __init__(self):
        self.kallsyms = {}
        self.kbase = pwndbg.gdblib.kernel.kbase()

        for mapping in pwndbg.gdblib.vmmap.get():
            # search for the first read-only page
            if mapping.vaddr <= self.kbase:
                continue
            if mapping.execute or mapping.write:
                continue

            self.ro_base = mapping.vaddr
            self.kernel_ro_mem = pwndbg.gdblib.memory.read(mapping.vaddr, mapping.memsz)
            break

        self.kernel_version = pwndbg.gdblib.kernel.krelease()
        self.token_table = self.find_token_table()
        self.token_index = self.find_token_index()
        self.markers = self.find_markers()
        self.offsets = self.find_offsets()
        self.r_base = self.find_relative_base()

        self.num_syms = self.find_num_syms()
        self.names = self.find_names()
        self.kernel_addresses = self.get_kernel_addresses()
        self.parse_symbol_table()

    def find_token_table(self) -> int:
        sequence_to_find = b"".join(b"%c\0" % i for i in range(ord("0"), ord("9") + 1))
        sequences_to_avoid = [b":\0", b"\0\0", b"\0\1", b"\0\2", b"ASCII\0"]

        position = 0

        candidates = []
        ascii_candidates = []

        while True:
            position = self.kernel_ro_mem.find(sequence_to_find, position + 1)
            if position == -1:
                break

            for seq in sequences_to_avoid:
                pos = position + len(sequence_to_find)
                if self.kernel_ro_mem[pos : pos + len(seq)] == seq:
                    break
            else:
                candidates.append(position)

                if (
                    chr(self.kernel_ro_mem[pos : pos + 1][0])
                    in string.ascii_letters + string.digits + string.punctuation
                ):
                    ascii_candidates.append(position)

        if len(candidates) != 1:
            if len(ascii_candidates) == 1:
                candidates = ascii_candidates
            elif len(candidates) == 0:
                print(M.error("No candidates for token_table"))
                return None

        position = candidates[0]

        current_index = 0x30

        position -= 1
        for tokens_backwards in range(current_index):
            for chars_in_token in range(50):
                position -= 1
                assert position >= 0

                if self.kernel_ro_mem[position] == 0 or self.kernel_ro_mem[position] > ord("z"):
                    break

                if chars_in_token >= 50 - 1:
                    print("This structure is not a kallsyms_token_table")
                    return None

        position += 1
        position += -position % 4

        return position

    def find_token_index(self) -> int | None:
        position = self.token_table

        token_table_head = self.kernel_ro_mem[position : position + 256]

        token_offsets = [p16(0)]

        pos = 0

        while True:
            pos = token_table_head.find(b"\0", pos + 1)
            if pos == -1:
                break
            token_offsets.append(p16(pos + 1))

        seq_to_find = b"".join(token_offsets)

        position = self.kernel_ro_mem.find(seq_to_find, self.token_table)
        if position == -1:
            print(M.error("Unable to find the kallsyms_token_index"))
            return None

        return position

    def find_markers(self) -> int | None:
        if self.kernel_version < (4, 20):
            elem_size = 8
        else:
            elem_size = 4

        seq_to_find = b"\0" * elem_size

        position = self.token_table - 1

        while position > 0 and self.kernel_ro_mem[position] == 0:
            position -= 1

        for _ in range(32):
            position = self.kernel_ro_mem.rfind(seq_to_find, 0, position)

            if position == -1:
                print(M.error("Failed to find kallsyms_markers"))
                return None

            position -= position % elem_size  # aligning

            entries = unpack_from("<4I", self.kernel_ro_mem, position)

            if entries[0] != 0:
                continue

            for i in range(1, len(entries)):
                if entries[i - 1] + 0x200 > entries[i] or entries[i - 1] + 0x4000 < entries[i]:
                    break
            else:
                return position

        return None

    def find_offsets(self):
        # searches for kallsyms_offsets

        forward_search = self.kernel_version >= (6, 4)
        position = self.token_index if forward_search else self.markers - 8

        while True:
            qword = u64(self.kernel_ro_mem[position : position + 8])
            if qword & 0xFFFFFFFF == 0:
                return position

            position += 8 if forward_search else -8

        return None

    def find_relative_base(self):
        position = self.offsets

        while True:
            x = u64(self.kernel_ro_mem[position : position + 8])

            if x & 0xFFF == 0 and (x >> 48) & 0xFFFF == 0xFFFF:
                return position

            position = position + 8

        return None

    def find_num_syms(self):
        if self.kernel_version < (6, 4):
            return self.r_base + 8
        else:
            # num_syms is likely to be found behind linux_banner symbol
            pattern = rb"Linux[^0-9]*?(\d+\.\d+\.\d+)"

            matches = re.finditer(pattern, self.kernel_ro_mem)

            for match in matches:
                last_match = match

            if last_match:
                position = last_match.start(1)

            while True:
                position = position + 1

                if self.kernel_ro_mem[position] == 0:
                    # found end of linux_banner string
                    break

            position = (position + 7) & ~7
            return position

    def find_names(self):
        return self.num_syms + 8

    def get_kernel_addresses(self):
        signed = lambda num: (num & 0xFFFFFFFF) - 0x100000000 if num & 0x80000000 else num
        kernel_addresses = []
        kconfig_ = pwndbg.gdblib.kernel.kconfig()
        position = self.offsets
        rbase = u64(self.kernel_ro_mem[self.r_base : self.r_base + 8])
        nsyms = u64(self.kernel_ro_mem[self.num_syms : self.num_syms + 8])
        abs_percpu = kconfig_.get("CONFIG_KALLSYMS_ABSOLUTE_PERCPU")
        for _ in range(nsyms):
            offset = u32(self.kernel_ro_mem[position : position + 4])

            if abs_percpu == "y" or abs_percpu is None:
                offset = signed(offset)
                if offset < 0:
                    offset = rbase - 1 - offset
                else:
                    offset = rbase + offset
            else:
                offset = rbase + offset

            kernel_addresses.append(offset)

            position += 4

        return kernel_addresses

    def parse_symbol_table(self):
        tokens = self.get_token_table()
        symbol_names = []
        position = self.names
        numsyms = u64(self.kernel_ro_mem[self.num_syms : self.num_syms + 8])

        for _ in range(numsyms):
            length = self.kernel_ro_mem[position]
            position += 1

            symbol_name = ""
            for _ in range(length):
                symbol_token_index = self.kernel_ro_mem[position]
                symbol_token = tokens[symbol_token_index]
                position += 1
                symbol_name += symbol_token
            symbol_names.append(symbol_name)

        for addr, name in zip(self.kernel_addresses, symbol_names):
            self.kallsyms[name[1:]] = (addr, name[0])

    def get_token_table(self):
        tokens = []
        position = self.token_table

        for num_token in range(256):
            token = ""
            while self.kernel_ro_mem[position]:
                token += chr(self.kernel_ro_mem[position])
                position += 1
            position += 1
            tokens.append(token)

        return tokens
