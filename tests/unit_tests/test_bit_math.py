from __future__ import annotations

import pwndbg.lib.disasm.helpers as bit_math

# We must import the function under test after all the mocks are imported


def test_to_signed():
    assert bit_math.to_signed(0b0100_0000, 8) == 0b0100_0000
    assert bit_math.to_signed(0b1000_0000, 8) == -128

    assert bit_math.to_signed(0xFFFFFFFF_FFFFFFFF, 64) == -1
    assert bit_math.to_signed(0x7FFFFFFF_FFFFFFFF, 64) == 0x7FFFFFFF_FFFFFFFF

    assert bit_math.to_signed(0xFFFF_FFFF, 32) == -1
    assert bit_math.to_signed(0x8000_0000, 32) == -(2**31)

    # Ignore higher bits
    assert bit_math.to_signed(0xF_FF, 8) == -1


def test_lsl():
    assert bit_math.logical_shift_left(0b1000_0000, 1, 8) == 0
    assert bit_math.logical_shift_left(0b0100_0000, 1, 8) == 0b1000_0000
    assert bit_math.logical_shift_left(0b1111_1111, 1, 8) == 0b1111_1110
    assert bit_math.logical_shift_left(0b1111_1111, 5, 8) == 0b1110_0000


def test_lsr():
    assert bit_math.logical_shift_right(0b1000_0000, 1, 8) == 0b0100_0000
    assert bit_math.logical_shift_right(0b0100_0000, 1, 8) == 0b0010_0000
    assert bit_math.logical_shift_right(0b1111_1111, 1, 8) == 0b0111_1111
    assert bit_math.logical_shift_right(0b1111_1111, 5, 8) == 0b0000_0111
    # Should truncate to bit_width before operation
    assert bit_math.logical_shift_right(0b1_0000_0000, 1, 8) == 0


def test_ror():
    assert bit_math.rotate_right(0b1000_0001, 1, 8) == 0b1100_0000
    assert bit_math.rotate_right(0b0100_0000, 1, 8) == 0b0010_0000
    assert bit_math.rotate_right(0b0100_0000, 4, 8) == 0b0000_0100
    assert bit_math.rotate_right(0b1111_1111, 1, 8) == 0b1111_1111
    assert bit_math.rotate_right(0b1110_1111, 5, 8) == 0b0111_1111

    # Should truncate to bit_width before operation
    assert bit_math.rotate_right(0b1_0000_0000, 1, 8) == 0
    assert bit_math.rotate_right(0b1_0111_1111, 1, 8) == 0b1011_1111


def test_asr():
    # Unsigned numbers should be the same
    assert bit_math.arithmetic_shift_right(0b0100_0000, 1, 8) == bit_math.logical_shift_right(
        0b0100_0000, 1, 8
    )
    assert bit_math.arithmetic_shift_right(0xFFFF_FF, 1, 32) == bit_math.logical_shift_right(
        0xFFFF_FF, 1, 32
    )
    assert bit_math.arithmetic_shift_right(0xFFFF_FF, 6, 32) == bit_math.logical_shift_right(
        0xFFFF_FF, 6, 32
    )

    assert bit_math.arithmetic_shift_right(0b1000_0000, 1, 8) == -64
    assert bit_math.arithmetic_shift_right(0b1000_0000, 2, 8) == -32
    assert bit_math.arithmetic_shift_right(0b1000_0000, 7, 8) == -1

    # Should truncate to bit_width before operation
    assert bit_math.arithmetic_shift_right(0b1_0000_0000, 1, 8) == 0
    assert bit_math.arithmetic_shift_right(0b1_0111_1111, 7, 8) == 0

    # Unsigned number shifted
    assert bit_math.arithmetic_shift_right(0x70000000_00000000, 62, 64) == 1
    assert bit_math.arithmetic_shift_right(0x70000000_00000000, 63, 64) == 0
