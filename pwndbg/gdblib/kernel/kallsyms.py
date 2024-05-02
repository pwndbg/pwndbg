from __future__ import annotations

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

        mapping = pwndbg.gdblib.kernel.get_readonly_mapping()
        self.r_base = mapping.vaddr
        self.kernel_ro_mem = pwndbg.gdblib.memory.read(mapping.vaddr, mapping.memsz)

        self.kernel_version = pwndbg.gdblib.kernel.krelease()
        self.is_offsets = False

        self.rbase_offset = 0

        self.token_table = self.find_token_table()
        self.token_index = self.find_token_index()
        self.markers = self.find_markers()
        self.num_syms = self.find_num_syms()
        self.offsets = self.find_offsets()

        if self.is_offsets:
            self.rbase_offset = self.find_relative_base()

        self.names = self.find_names()
        self.kernel_addresses = self.get_kernel_addresses()
        self.parse_symbol_table()

    def find_token_table(self) -> int:
        """
        This function searches for the kallsyms_token_table structure in the kernel memory.

        The kallsyms_token_table contains 256 zero-terminated tokens from which symbol names are built.

        Example sructure:

        TODO: add structure
        """
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

                if 32 <= self.kernel_ro_mem[pos : pos + 1][0] < 126:
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
                    print(M.error("This structure is not a kallsyms_token_table"))
                    return None

        position += 1
        position += -position % 4

        return position

    def find_token_index(self) -> int | None:
        """
        This function searches for the kallsyms_token_index structure in the kernel memory
        starting at kallsyms_token_table. The token index table provides offsets into the kallsyms_token_table
        for each 256 byte-valued sub-table.

        The kallsyms_token_index is typically located immediately after
        the kallsyms_token_table in the kernel's read-only data section.

        Example structure:

        TODO: add
        """
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
        """
        This function searches for the kallsyms_markers structure in the kernel memory
        starting at kallsyms_token_table and search backwards. The markers table contains
        offsets to the corresponding symbol name for each kernel symbol.

        The kallsyms_markers table is typically located immediately before the kallsyms_token_table
        in the kernel's read-only data section.

        Example structure:
        TODO: add
        """
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
            size_marker = {4: "I", 8: "Q"}[elem_size]

            entries = unpack_from(f"<4{size_marker}", self.kernel_ro_mem, position)

            if entries[0] != 0:
                continue

            for i in range(1, len(entries)):
                if entries[i - 1] + 0x200 > entries[i] or entries[i - 1] + 0x4000 < entries[i]:
                    break
            else:
                return position

        return None

    def find_num_syms(self):
        """
        This function searches for the kallsyms_num_syms variable in the kernel memory
        starting at kallsyms_markers. The kallsyms_num_syms holds the number of kernel symbols
        in the symbol table.

        The kallsyms_num_syms variable is typically located before the kallsyms_names table in the kernel's
        read-only data section.

        In newer kernel versions the kallsyms_num_syms is immediately behind the linux_banner and in older version
        its behind kallsyms_base_relative or kallsyms_addresses (it depends on CONFIG_KALLSYMS_BASE_RELATIVE y/n)
        """
        if self.kernel_version < (6, 4):
            # try to find num_syms first by walking backwards and looking
            # for data like this a kernel address followed by num_syms
            # 0xffffffff823f8000	0x000000000001417c
            position = self.markers - 8

            while True:
                qword = u64(self.kernel_ro_mem[position : position + 8])
                if (qword >> 32) & 0xFFFFFFFF == 0 and qword > 0:
                    before_qword = u64(self.kernel_ro_mem[position - 8 : position])
                    if (before_qword >> 48) & 0xFFFF == 0xFFFF and (before_qword & 0xFFF) == 0:
                        # should be kallsyms_num_syms
                        return position

                position -= 8
        else:
            # search from kallsyms_markers backwards and look for the linux_banner symbol
            # the kallsyms_num_syms should be behind the linux_banner string
            position = self.kernel_ro_mem.rfind(b"Linux version", 0, self.markers - 8)

            if position == -1:
                return None

            while True:
                position = position + 1
                if self.kernel_ro_mem[position] == 0:
                    break

            position = (position + 7) & ~7  # alignment
            return position

    def find_offsets(self):
        """
        This function searches for the kallsyms_offsets/kallsyms_addresses table in the kernel memory
        starting at kallsyms_token_index. The offsets/addresses table containts offsets / addresses of each
        symbol in the kernel.

        The kallsyms_addresses is typically located before the kallsyms_num_syms variable in the kernel's read-only
        data section.

        Example structure:
        TODO: add
        """
        forward_search = self.kernel_version >= (6, 4)

        if forward_search:
            position = self.token_index
            self.is_offsets = True
        else:
            # kallsyms_offsets is at the top
            position = self.num_syms
            nsyms = u64(self.kernel_ro_mem[position : position + 8])

            if (
                self.kbase - 0x20000
                < u64(self.kernel_ro_mem[position - 8 : position])
                <= self.kbase
            ):
                # it should be kallsyms_offsets
                self.is_offsets = True
                position -= 8

                dword = u32(self.kernel_ro_mem[position - 4 : position])

                if dword == 0x0:
                    position -= 4

                return position - (nsyms * 4)

            return position - (nsyms * 8)

        while True:
            qword = u64(self.kernel_ro_mem[position : position + 8])
            if qword & 0xFFFFFFFF == 0:
                return position

            position += 8

        return None

    def find_relative_base(self):
        """
        This function searches for the kallsyms_relative_base variable in the kernel memory.
        The relative base is used to calculate the actual virtual addresses of symbols from
        their offsets in the kallsyms_offsets table.

        The kallsyms_relative_base variable is typically located after the kallsyms_offsets table
        in the kernel's read-only data section.
        """
        position = self.offsets
        nsyms = u64(self.kernel_ro_mem[self.num_syms : self.num_syms + 8])

        position = position + (nsyms * 4)
        position = (position + 7) & ~7

        return position

    def find_names(self):
        return self.num_syms + 8

    def get_kernel_addresses(self):
        kernel_addresses = []

        rbase = u64(self.kernel_ro_mem[self.rbase_offset : self.rbase_offset + 8])
        nsyms = u64(self.kernel_ro_mem[self.num_syms : self.num_syms + 8])
        size_marker = "i" if self.is_offsets else "Q"
        kernel_addresses = list(
            unpack_from(f"<{nsyms}{size_marker}", self.kernel_ro_mem, self.offsets)
        )

        if not self.is_offsets:
            return kernel_addresses

        number_of_negative_items = len([offset for offset in kernel_addresses if offset < 0])
        abs_percpu = number_of_negative_items / len(kernel_addresses) >= 0.5

        for idx, offset in enumerate(kernel_addresses):
            if abs_percpu:
                if offset < 0:
                    offset = rbase - 1 - offset
                else:
                    offset = rbase + offset
            else:
                offset = rbase + offset

            kernel_addresses[idx] = offset

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
