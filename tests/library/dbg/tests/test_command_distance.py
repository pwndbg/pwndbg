from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")
LINKED_LISTS_BINARY = get_binary("linked-lists.native.out")
MULTIPLE_THREADS_BINARY = get_binary("multiple_threads.native.out")


@pwndbg_test
async def test_command_distance(ctrl: Controller):
    import pwndbg.aglib

    await ctrl.launch(REFERENCE_BINARY)

    # Test against regs
    sp = pwndbg.aglib.regs.sp
    result = await ctrl.execute_and_capture("distance $sp $sp+0x10")
    assert result == f"{sp:#x}->{sp + 0x10:#x} is 0x10 bytes (0x2 words)\n"

    # Test if it works with symbols
    pc = pwndbg.aglib.regs.pc

    main = pwndbg.aglib.symbol.lookup_symbol_addr("main")
    break_here = pwndbg.aglib.symbol.lookup_symbol_addr("break_here")

    diff = break_here - main

    # Test symbol (function address) and its proper &symbol address
    for sym1 in ("main", "&main"):
        for sym2 in ("break_here", "&break_here"):
            result = await ctrl.execute_and_capture(f"distance {sym1} {sym2}")
            assert (
                result == f"{main:#x}->{break_here:#x} is {diff:#x} bytes ({diff // 8:#x} words)\n"
            )

    # Test if it works with reg + symbol
    diff = break_here - pc
    result = await ctrl.execute_and_capture("distance $pc &break_here")
    assert result == f"{pc:#x}->{break_here:#x} is {diff:#x} bytes ({diff // 8:#x} words)\n"

    # Test if it works with symbol + reg
    diff = pc - break_here
    result = await ctrl.execute_and_capture("distance &break_here $pc")
    assert result == f"{break_here:#x}->{pc:#x} is {diff:#x} bytes ({diff // 8:#x} words)\n"


@pwndbg_test
async def test_command_distance_struct_symbols(ctrl: Controller) -> None:
    import pwndbg.aglib

    await ctrl.launch(LINKED_LISTS_BINARY)

    node_a = pwndbg.aglib.symbol.lookup_symbol_addr("node_a")
    node_b = pwndbg.aglib.symbol.lookup_symbol_addr("node_b")
    assert node_a is not None and node_b is not None

    diff = node_b - node_a

    # Test struct symbols and their proper &symbol addresses
    for sym1 in ("node_a", "&node_a"):
        for sym2 in ("node_b", "&node_b"):
            result = await ctrl.execute_and_capture(f"distance {sym1} {sym2}")
            assert result == f"{node_a:#x}->{node_b:#x} is {diff:#x} bytes ({diff // 8:#x} words)\n"


@pwndbg_test
async def test_command_distance_typedef_union_symbol(ctrl: Controller) -> None:
    import pwndbg.aglib

    await ctrl.launch(MULTIPLE_THREADS_BINARY)

    # sem_t is a typedef'd union
    sem = pwndbg.aglib.symbol.lookup_symbol_addr("sem")
    assert sem is not None

    result = await ctrl.execute_and_capture("distance sem &sem")
    assert result == f"{sem:#x}->{sem:#x} is 0x0 bytes (0x0 words)\n"
