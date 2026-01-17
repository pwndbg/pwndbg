from __future__ import annotations


# common functions
def hex2ptr_common(arg: str) -> int:
    """Converts a hex string to a little-endian integer address."""
    arg = "".join(filter(str.isalnum, arg))
    if len(arg) % 2 != 0:
        raise ValueError("Hex string must contain an even number of characters.")
    try:
        big_endian_num = int(arg, 16)
        num_bytes = big_endian_num.to_bytes((len(arg) + 1) // 2, byteorder="big")
        little_endian_num = int.from_bytes(num_bytes, byteorder="little")
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}")
    return little_endian_num
