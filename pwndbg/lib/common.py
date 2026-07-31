from __future__ import annotations


def parse_byte_patterns(spec: str) -> set[int]:
    """Expands a comma-separated list of hex byte patterns into the bytes they match.

    Each pattern is exactly two hex nibbles, where ``?`` matches any nibble. An
    optional ``0x`` prefix is accepted and whitespace around a pattern is ignored.

    For example, ``"00,4?"`` matches ``0x00`` along with every byte from ``0x40``
    to ``0x4f``.
    """
    matches: set[int] = set()

    for raw in spec.split(","):
        pattern = raw.strip().lower().removeprefix("0x")

        if not pattern:
            raise ValueError("Empty byte pattern; expected two hex nibbles such as '00' or '4?'")

        if len(pattern) != 2:
            raise ValueError(
                f"Invalid byte pattern {pattern!r}: expected two hex nibbles such as '00' or '4?'"
            )

        nibbles = []
        for char in pattern:
            if char == "?":
                nibbles.append(range(16))
            elif char in "0123456789abcdef":
                nibbles.append(range(int(char, 16), int(char, 16) + 1))
            else:
                raise ValueError(
                    f"Invalid character {char!r} in byte pattern {pattern!r}: "
                    "expected a hex digit or '?'"
                )

        for high in nibbles[0]:
            for low in nibbles[1]:
                matches.add(high << 4 | low)

    return matches


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
