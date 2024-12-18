from __future__ import annotations

from re import match
from re import search
from struct import unpack_from
from typing import Dict
from typing import Tuple

from pwnlib.util.packing import p16
from pwnlib.util.packing import u32
from pwnlib.util.packing import u64

import pwndbg.aglib
import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.lib.cache
import pwndbg.search


@pwndbg.lib.cache.cache_until("start")
def get() -> Dict[str, Tuple[int, str]]:
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
        self.kallsyms: Dict[str, Tuple[int, str]] = {}
        self.kbase = pwndbg.aglib.kernel.kbase()

        mapping = pwndbg.aglib.kernel.get_first_kernel_ro()
        assert mapping is not None, "kernel memory mappings are missing"

        self.r_base = mapping.vaddr
        self.kernel_ro_mem = pwndbg.aglib.memory.read(mapping.vaddr, mapping.memsz)

        self.kernel_version = pwndbg.aglib.kernel.krelease()
        self.is_offsets = False

        self.rbase_offset = 0

        self.is_big_endian = None

        self.token_table = self.find_token_table()
        self.is_uncompressed = False

        if self.token_table is None:
            if not self.find_names_uncompressed():
                return
            print(M.info("Detected Uncompressed Kallsyms"))
            self.is_uncompressed = True
            self.markers = self.find_markers_uncompressed()
        else:
            print(M.info("Detected Compressed Kallsyms"))
            self.token_index = self.find_token_index()
            self.markers = self.find_markers()

        self.num_syms = self.find_num_syms()
        self.offsets = self.find_offsets()

        if self.is_offsets:
            self.rbase_offset = self.find_relative_base()

        self.names = self.find_names()
        self.kernel_addresses = self.get_kernel_addresses()
        self.parse_symbol_table()
        print(M.info(f"Found {len(self.kallsyms)} ksymbols"))

    def find_token_table(self) -> int:
        """
        This function searches for the kallsyms_token_table structure in the kernel memory.
        The kallsyms_token_table contains 256 zero-terminated tokens from which symbol names are built.
        Example structure:
        0xffffffff827b2f00:	"mm"
        0xffffffff827b2f03:	"tim"
        0xffffffff827b2f07:	"bu"
        0xffffffff827b2f0a:	"ode_"
        0xffffffff827b2f0f:	"robestub"
        <SKIPPED>
        0xffffffff827b2fdb:	"0"
        0xffffffff827b2fdd:	"1"
        0xffffffff827b2fdf:	"2"
        0xffffffff827b2fe1:	"3"
        0xffffffff827b2fe3:	"4"
        0xffffffff827b2fe5:	"5"
        0xffffffff827b2fe7:	"6"
        0xffffffff827b2fe9:	"7"
        0xffffffff827b2feb:	"8"
        0xffffffff827b2fed:	"9"
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
                # print(M.error("No candidates for token_table, maybe uncompressed kallsyms"))
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
        0xffffffff827b3288:	0x0000	0x0003	0x0007	0x000a	0x000f	0x0018	0x001f	0x0023
        0xffffffff827b3298:	0x0027	0x0031	0x0035	0x0038	0x003b	0x0043	0x0047	0x004a
        0xffffffff827b32a8:	0x004f	0x0053	0x0056	0x0059	0x005d	0x0061	0x0067	0x006b
        0xffffffff827b32b8:	0x006e	0x0071	0x0076	0x007c	0x0080	0x0088	0x008b	0x008f
        0xffffffff827b32c8:	0x0094	0x0098	0x009b	0x009f	0x00a3	0x00a8	0x00ab	0x00b0
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
        0xffffffff827b2430:	0x00000000	0x00000b2a	0x00001762	0x000023f6
        0xffffffff827b2440:	0x00002fe4	0x00003c9d	0x0000487c	0x000056fd
        0xffffffff827b2450:	0x00006597	0x000073b9	0x000081be	0x00008f21
        0xffffffff827b2460:	0x00009c94	0x0000a958	0x0000b632	0x0000c193
        0xffffffff827b2470:	0x0000ce0b	0x0000db98	0x0000ea3e	0x0000f80a
        0xffffffff827b2480:	0x000105be	0x000112d3	0x00011f8c	0x00012d75
        0xffffffff827b2490:	0x0001384d	0x0001446e	0x00015138	0x00015d8c
        """
        if self.kernel_version < (4, 20):
            elem_size = pwndbg.aglib.arch.ptrsize
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
            # try to find num_syms by walking backwards and looking
            # for data like this: a kernel address followed by num_syms
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
        0xffffffff827b3488:	0x00000000	0x00000000	0x00001000	0x00002000
        0xffffffff827b3498:	0x00006000	0x0000b000	0x0000c000	0x0000d000
        0xffffffff827b34a8:	0x00015000	0x00015008	0x00015010	0x00015018
        0xffffffff827b34b8:	0x00015020	0x00015022	0x00015030	0x00015050
        0xffffffff827b34c8:	0x00015450	0x00015460	0x00015860	0x00015888
        0xffffffff827b34d8:	0x00015890	0x00015898	0x000158a0	0x000159c0
        """
        forward_search = self.kernel_version >= (6, 4)

        if forward_search and not self.is_uncompressed:
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
        # TODO: nsyms is 4 bytes long not 8
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
        if not self.is_uncompressed:
            tokens = []
            position = self.token_table

            for num_token in range(256):
                token = ""
                while self.kernel_ro_mem[position]:
                    token += chr(self.kernel_ro_mem[position])
                    position += 1
                position += 1
                tokens.append(token)

        else:
            tokens = [chr(i) for i in range(256)]

        return tokens

    def find_names_uncompressed(self):
        # Find the length byte-separated symbol names
        ksymtab_match = search(
            rb"(?:[\x05-\x23][TWtbBrRAdD][a-z0-9_.]{4,34}){14}", self.kernel_ro_mem
        )

        if not ksymtab_match:
            print(M.error("Failed to find kallsyms"))
            return None

        kallsyms_names__offset = ksymtab_match.start(0)

        # Count the number of symbol names
        position = kallsyms_names__offset
        num_syms = 0

        while position + 1 < len(self.kernel_ro_mem):
            if (
                self.kernel_ro_mem[position] < 2
                or chr(self.kernel_ro_mem[position + 1]).lower() not in "abdrtvwginpcsu-?"
            ):
                break

            symbol_name_and_type = self.kernel_ro_mem[
                position + 1 : position + 1 + self.kernel_ro_mem[position]
            ]

            if not match(rb"^[\x21-\x7e]+$", symbol_name_and_type):
                break

            position += 1 + self.kernel_ro_mem[position]
            num_syms += 1

        if num_syms < 100:
            print(M.error("Failed to find kallsyms"))
            return None

        self.end_of_kallsyms_names_uncompressed = position
        return True

    def find_markers_uncompressed(self):
        """
        This function searches for the kallsyms_markers structure in the kernel memory
        Original Source: https://github.com/marin-m/vmlinux-to-elf/blob/master/vmlinux_to_elf/kallsyms_finder.py
        """
        position = self.end_of_kallsyms_names_uncompressed
        position += -position % 4

        max_number_of_space_between_two_nulls = 0

        # Go just after the first chunk of non-null bytes

        # while position + 1 < len(self.kernel_img) and self.kernel_img[position + 1] == 0:
        #     position += 1

        while position + 1 < len(self.kernel_ro_mem) and self.kernel_ro_mem[position + 1] == 0:
            position += 1

        for null_separated_bytes_chunks in range(20):
            num_non_null_bytes = 1  # we always start at a non-null byte in this loop
            num_null_bytes = (
                1  # we will at least encounter one null byte before the end of this loop
            )

            while True:
                position += 1
                assert position >= 0

                if self.kernel_ro_mem[position] == 0:
                    break
                num_non_null_bytes += 1

            while True:
                position += 1
                assert position >= 0

                if self.kernel_ro_mem[position] != 0:
                    break
                num_null_bytes += 1

            max_number_of_space_between_two_nulls = max(
                max_number_of_space_between_two_nulls, num_non_null_bytes + num_null_bytes
            )

        if (
            max_number_of_space_between_two_nulls % 2 == 1
        ):  # There may be a leap to a shorter offset in the latest processed entries
            max_number_of_space_between_two_nulls -= 1

        if max_number_of_space_between_two_nulls not in (2, 4, 8):
            print(M.error("Could not guess the architecture register size for kernel"))
            return None

        self.offset_table_element_size = max_number_of_space_between_two_nulls

        # Once the size of a long has been guessed, use it to find
        # the first offset (0)

        position = self.end_of_kallsyms_names_uncompressed
        position += -position % 4

        # Go just at the first non-null byte
        while position < len(self.kernel_ro_mem) and self.kernel_ro_mem[position] == 0:
            position += 1

        likely_is_big_endian = position % self.offset_table_element_size > 1
        if self.is_big_endian is None:  # Manual architecture specification
            self.is_big_endian = likely_is_big_endian

        if position % self.offset_table_element_size == 0:
            position += self.offset_table_element_size
        else:
            position += -position + self.offset_table_element_size

        position -= self.offset_table_element_size
        position -= self.offset_table_element_size

        position -= position % self.offset_table_element_size

        self.kallsyms_markers__offset = position

        # print('Found kallsyms_markers at file offset 0x%08x' % position)

        return position
