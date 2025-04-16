from __future__ import annotations


def to_signed(unsigned: int, bit_width: int):
    """
    Returns the signed number associated with the two's-complement binary representation of `unsigned`
    """
    unsigned = unsigned & ((1 << bit_width) - 1)
    extract_bit = 1 << (bit_width - 1)
    return unsigned - ((unsigned & extract_bit) << 1)


def logical_shift_left(n: int, shift_amt: int, bit_width: int):
    return (n << shift_amt) & ((1 << bit_width) - 1)


def logical_shift_right(n: int, shift_amt: int, bit_width: int):
    """
    `n` is truncated to the width of `bit_width` before the operation takes place.
    """
    n = n & ((1 << bit_width) - 1)
    return n >> shift_amt


def rotate_right(n: int, shift_amt: int, bit_width: int):
    """
    `n` is truncated to the width of `bit_width` before the operation takes place.
    """
    n = n & ((1 << bit_width) - 1)
    return ((n >> shift_amt) | (n << (bit_width - shift_amt))) & ((1 << bit_width) - 1)


def arithmetic_shift_right(n: int, shift_amt: int, bit_width: int):
    """
    This returns the value represented by the two's-complement binary representation of the final result.
    This means the result could be negative (if the top bit of the input is negative)

    `n` is truncated to the width of `bit_width` before the operation takes place.
    """
    n = n & ((1 << bit_width) - 1)

    result = logical_shift_right(n, shift_amt, bit_width)

    sign_extension_mask = (1 << (bit_width - shift_amt)) - 1
    # Replicate the sign bit if it's set
    if n & (1 << (bit_width - 1)):
        result |= ~sign_extension_mask

    return result
