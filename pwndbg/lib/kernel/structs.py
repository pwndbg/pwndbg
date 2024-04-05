from __future__ import annotations


class IDTEntry:
    """
    Represents an entry in the Interrupt Descriptor Table (IDT)

    The IDTEntry class stores information about an IDT entry, including its index,
    offset, segment selector, descriptor privilege level (DPL), gate type, and
    interrupt stack table (IST) index.

    https://wiki.osdev.org/Interrupt_Descriptor_Table
    """

    def __init__(self, entry):
        self.offset = None
        self.segment = None
        self.dpl = None
        self.type = None
        self.ist = None
        self.present = None

        if len(entry) == 8:
            self._parse_entry32(entry)
        elif len(entry) == 16:
            self._parse_entry64(entry)

    def _parse_entry32(self, entry):
        """
        Parse a 32-bit IDT entry.

                                Gate Descriptor (32-bit)
        63                                  48  47  45 44        40               32
        +------------------------------------+--+---+--+---------+----------------+
        |                                    |P |DPL|0 |Gate Type|  Reserved      |
        |    Offset 31..16                   |  |   |  |         |                |
        |                                    |  |   |  |         |                |
        +------------------+------------------+------------------+----------------+
        31                                   16                                   0
        +-------------------------------------+------------------+----------------+
        |                                     |                                   |
        |          Segment Selector           |           Offset 15..0            |
        |                                     |                                   |
        +------------------+------------------+------------------+----------------+
        """
        entry = int.from_bytes(entry, byteorder="little")

        self.offset = entry & 0xFFFF
        self.offset |= ((entry >> 48) & 0xFFFF) << 16

        self.segment = (entry >> 16) & 0xFFFF
        self.type = (entry >> 40) & 0xF
        self.dpl = (entry >> 45) & 0x3
        self.present = (entry >> 47) & 0x1

    def _parse_entry64(self, entry):
        """Parse a 64-bit IDT entry."""
        entry = int.from_bytes(entry, byteorder="little")

        self.offset = entry & 0xFFFF
        self.offset |= ((entry >> 48) & 0xFFFF) << 16
        self.offset |= ((entry >> 64) & 0xFFFFFFFF) << 32

        self.segment = (entry >> 16) & 0xFFFF
        self.ist = (entry >> 32) & 0x7
        self.type = (entry >> 40) & 0xF
        self.dpl = (entry >> 45) & 0x3
