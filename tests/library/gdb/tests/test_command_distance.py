from __future__ import annotations

import gdb

import pwndbg.aglib.regs

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.out")


def test_command_distance(start_binary):
    start_binary(REFERENCE_BINARY)

    # Test against regs
    rsp = pwndbg.aglib.regs.rsp
    result = gdb.execute("distance $rsp $rsp+0x10", to_string=True)
    assert result == f"{rsp:#x}->{rsp + 0x10:#x} is 0x10 bytes (0x2 words)\n"

    # Test if it works with symbols
    rip = pwndbg.aglib.regs.rip

    main = pwndbg.aglib.symbol.lookup_symbol_addr("main")
    break_here = pwndbg.aglib.symbol.lookup_symbol_addr("break_here")

    diff = break_here - main

    # Test symbol (function address) and its proper &symbol address
    for sym1 in ("main", "&main"):
        for sym2 in ("break_here", "&break_here"):
            result = gdb.execute(f"distance {sym1} {sym2}", to_string=True)
            assert result == f"{main:#x}->{break_here:#x} is {diff:#x} bytes ({diff//8:#x} words)\n"

    # Test if it works with reg + symbol
    diff = break_here - rip
    result = gdb.execute("distance $rip &break_here", to_string=True)
    assert result == f"{rip:#x}->{break_here:#x} is {diff:#x} bytes ({diff//8:#x} words)\n"

    # Test if it works with symbol + reg
    diff = rip - break_here
    result = gdb.execute("distance &break_here $rip", to_string=True)
    assert result == f"{break_here:#x}->{rip:#x} is {diff:#x} bytes ({diff//8:#x} words)\n"
