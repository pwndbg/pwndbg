from __future__ import annotations

# TODO: take these sorts of things from pwndbg.lib.functions

PROT_DICT = {
    "PROT_NONE": 0x0,
    "PROT_READ": 0x1,
    "PROT_WRITE": 0x2,
    "PROT_EXEC": 0x4,
}

FLAG_DICT = {
    "MAP_SHARED": 0x1,
    "MAP_PRIVATE": 0x2,
    "MAP_SHARED_VALIDATE": 0x3,
    "MAP_FIXED": 0x10,
    "MAP_ANONYMOUS": 0x20,
}
PROT_SHORT_DICT = {
    "R": PROT_DICT["PROT_READ"],
    "W": PROT_DICT["PROT_WRITE"],
    "X": PROT_DICT["PROT_EXEC"],
}


def from_string(mapping: dict[str, int], s: str) -> int:
    val = 0
    for k, v in mapping.items():
        if k in s:
            val |= v
    return val


def to_string(mapping: dict[str, int], n: int, *, default: str = "", sep: str = "|") -> str:
    if n == 0:
        return default
    ret = []
    for k, v in mapping.items():
        if n & v:
            ret.append(k)
    return sep.join(ret)


def prot_from_string(protstr: str) -> int:
    """
    Converts a protection string to an integer. Formats include:
     - A positive integer, like 3
     - A combination of r, w, and x, like rw
     - A combination of PROT_READ, PROT_WRITE, and PROT_EXEC, like PROT_READ|PROT_WRITE
    """
    protstr = protstr.upper()
    if "PROT" in protstr:
        return from_string(PROT_DICT, protstr)

    if all(x in "RWX" for x in protstr):
        return from_string(PROT_SHORT_DICT, protstr)
    try:
        return int(protstr, 0)
    except ValueError:
        raise ValueError(f"Invalid 'PROT' string {protstr!r}")


def prot_to_string(protval: int) -> str:
    return to_string(PROT_DICT, protval, default="PROT_NONE")


def flag_from_string(flagstr: str) -> int:
    """Heuristic to convert MAP_SHARED|MAP_FIXED to integer value."""
    flagstr = flagstr.upper()
    if "MAP" in flagstr:
        return from_string(FLAG_DICT, flagstr)
    try:
        return int(flagstr, 0)
    except ValueError:
        raise ValueError(f"Invalid 'MAP_' string {flagstr!r}")
