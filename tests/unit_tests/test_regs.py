from __future__ import annotations

from pwndbg.lib.regs import PsuedoEmulatedRegisterFile
from pwndbg.lib.regs import aarch64
from pwndbg.lib.regs import amd64
from pwndbg.lib.regs import mips


def test_emulated_register_set_amd64():
    """
    These tests check that register writes and reads are implemented correctly.

    RAX = 64-bits
    EAX = low 32-bits    // All writes EAX will zero out the high 32-bits of RAX
    AX  = low 16-bits
    AH  = top half of AX
    AL  = bottom half of AX
    """
    new = PsuedoEmulatedRegisterFile(amd64, 8)

    new.write_register("rax", -1)

    assert new.read_register("al") == 0xFF
    assert new.read_register("ah") == 0xFF
    assert new.read_register("ax") == 0xFFFF
    assert new.read_register("eax") == 0xFFFF_FFFF
    assert new.read_register("rax") == 0xFFFF_FFFF_FFFF_FFFF

    new.invalidate_all_registers()

    new.write_register("al", 0b1111)

    assert new.read_register("al") == 0b1111
    assert new.read_register("ah") is None
    assert new.read_register("ax") is None
    assert new.read_register("eax") is None
    assert new.read_register("rax") is None

    new.invalidate_all_registers()

    new.write_register("eax", 0xFFFF_AABB)

    assert new.read_register("al") == 0xBB
    assert new.read_register("ah") == 0xAA
    assert new.read_register("ax") == 0xAABB
    assert new.read_register("eax") == 0xFFFF_AABB
    # The 32-bit write here zero-extends to the entire register so we can read RAX
    assert new.read_register("rax") == 0x000_0000_FFFF_AABB

    new.invalidate_all_registers()

    new.write_register("ah", 0x11)
    assert new.read_register("al") is None
    assert new.read_register("ah") == 0x11
    assert new.read_register("ax") is None
    assert new.read_register("eax") is None
    assert new.read_register("rax") is None

    new.invalidate_all_registers()

    new.write_register("ax", 0x1234)
    assert new.read_register("al") == 0x34
    assert new.read_register("ah") == 0x12
    assert new.read_register("ax") == 0x1234
    assert new.read_register("eax") is None
    assert new.read_register("rax") is None


def test_emulated_register_set_amd64_more():
    new = PsuedoEmulatedRegisterFile(amd64, 8)

    # Unwritten value should return None
    assert new.read_register("rbx") is None

    new.write_register("ah", 0x22)
    new.write_register("al", 0x11)

    assert new.read_register("al") == 0x11
    assert new.read_register("ah") == 0x22
    assert new.read_register("ax") == 0x2211
    assert new.read_register("eax") is None
    assert new.read_register("rax") is None

    new.write_register("eax", 0xFF00_0000)

    assert new.read_register("al") == 0x00
    assert new.read_register("ah") == 0x00
    assert new.read_register("ax") == 0x0000
    assert new.read_register("eax") == 0xFF00_0000
    # Writes to 32-bit registers zero-extend to the entire register
    assert new.read_register("rax") == 0xFF00_0000

    new.write_register("al", 0x01)

    assert new.read_register("al") == 0x01
    assert new.read_register("ah") == 0x00
    assert new.read_register("ax") == 0x0001
    assert new.read_register("eax") == 0xFF00_0001
    assert new.read_register("rax") == 0xFF00_0001

    new.write_register("rax", 0x01)

    assert new.read_register("al") == 0x01
    assert new.read_register("ah") == 0x00
    assert new.read_register("ax") == 0x0001
    assert new.read_register("eax") == 0x0000_0001
    assert new.read_register("rax") == 0x0000_0001

    new.invalidate_all_registers()

    new.write_register("rax", -1)
    new.write_register("eax", -1)

    # The 32-bit write here zero-extends to the entire register.
    assert new.read_register("eax") == 0xFFFF_FFFF
    assert new.read_register("rax") == 0xFFFF_FFFF

    new.invalidate_all_registers()

    assert new.read_register("al") is None
    assert new.read_register("ah") is None
    assert new.read_register("ax") is None
    assert new.read_register("eax") is None
    assert new.read_register("rax") is None

    new.write_register("ah", -1)

    assert new.read_register("al") is None
    assert new.read_register("ah") == 0xFF
    assert new.read_register("ax") is None
    assert new.read_register("eax") is None
    assert new.read_register("rax") is None

    new.write_register("bh", 0xFF)

    assert new.read_register("bl") is None
    assert new.read_register("bh") == 0xFF
    assert new.read_register("bx") is None
    assert new.read_register("ebx") is None
    assert new.read_register("rbx") is None


def test_emulated_register_set_amd64_invalidate():
    new = PsuedoEmulatedRegisterFile(amd64, 8)

    new.write_register("rax", -1)

    new.invalidate_register("eax")

    assert new.read_register("al") is None
    assert new.read_register("ah") is None
    assert new.read_register("ax") is None
    assert new.read_register("eax") is None
    assert new.read_register("rax") is None

    new.write_register("rax", -1)
    new.invalidate_register("al")

    # "ah" register doesn't overlap with "al"
    assert new.read_register("al") is None
    assert new.read_register("ah") == 0xFF
    assert new.read_register("ax") is None
    assert new.read_register("eax") is None
    assert new.read_register("rax") is None

    # Write a value back to al. All the others bits are still preserved
    new.write_register("al", 0xAA)

    assert new.read_register("al") == 0xAA
    assert new.read_register("ah") == 0xFF
    assert new.read_register("ax") == 0xFFAA
    assert new.read_register("eax") == 0xFFFF_FFAA
    assert new.read_register("rax") == 0xFFFF_FFFF_FFFF_FFAA

    new.invalidate_register("eax")
    new.write_register("eax", -1)

    assert new.read_register("al") == 0xFF
    assert new.read_register("ah") == 0xFF
    assert new.read_register("ax") == 0xFFFF
    assert new.read_register("eax") == 0xFFFF_FFFF
    assert new.read_register("rax") == 0xFFFF_FFFF


def test_emulate_register_file_amd64_sign_extension():
    new = PsuedoEmulatedRegisterFile(amd64, 8)

    # This will sign extend the value to EAX, since the top bit in 0xFF is 1.
    new.write_register("eax", 0xFF, source_width=1, sign_extend=True)

    assert new.read_register("al") == 0xFF
    assert new.read_register("ah") == 0xFF
    assert new.read_register("ax") == 0xFFFF
    assert new.read_register("eax") == 0xFFFF_FFFF
    assert new.read_register("rax") == 0xFFFF_FFFF

    new.write_register("eax", 0xFF, source_width=2, sign_extend=True)

    assert new.read_register("al") == 0xFF
    assert new.read_register("ah") == 0x00
    assert new.read_register("ax") == 0x00FF
    assert new.read_register("eax") == 0x0000_00FF
    assert new.read_register("rax") == 0x0000_00FF


def test_emulated_register_set_aarch64():
    new = PsuedoEmulatedRegisterFile(aarch64, 8)

    new.write_register("w0", 0xFFFF_AABB)

    # The 32-bit write here zero-extends to the entire register
    assert new.read_register("x0") == 0x000_0000_FFFF_AABB
    assert new.read_register("w0") == 0xFFFF_AABB

    new.write_register("x0", -1)

    assert new.read_register("w0") == 0xFFFF_FFFF
    assert new.read_register("x0") == 0xFFFF_FFFF_FFFF_FFFF


def test_emulated_register_set_mips():
    new = PsuedoEmulatedRegisterFile(mips, 4)

    new.write_register("v0", 0xFFFF_AABB)

    assert new.read_register("v0") == 0xFFFF_AABB

    new = PsuedoEmulatedRegisterFile(mips, 8)

    new.write_register("v0", 0xFF_FFFF_AABB)

    assert new.read_register("v0") == 0xFF_FFFF_AABB
