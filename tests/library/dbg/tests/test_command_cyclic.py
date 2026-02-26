from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_command_cyclic_value(ctrl: Controller) -> None:
    """
    Tests lookup on a constant value
    """
    from pwnlib.util.cyclic import cyclic

    import pwndbg.aglib

    await ctrl.launch(REFERENCE_BINARY)

    ptr_size = pwndbg.aglib.arch.ptrsize
    test_offset = 37
    pattern = cyclic(length=80)
    val = int.from_bytes(pattern[test_offset : test_offset + ptr_size], pwndbg.aglib.arch.endian)
    out = await ctrl.execute_and_capture(f"cyclic -l {hex(val)}")

    assert out == (
        "Finding cyclic pattern of 4 bytes: b'aaak' (hex: 0x6161616b)\nFound at offset 37\n"
    )


@pwndbg_test
async def test_command_cyclic_register(ctrl: Controller) -> None:
    """
    Tests lookup on a register
    """
    from pwnlib.util.cyclic import cyclic

    import pwndbg.aglib

    await ctrl.launch(REFERENCE_BINARY)

    reg_name = pwndbg.aglib.regs.gpr[0]
    ptr_size = pwndbg.aglib.arch.ptrsize

    test_offset = 45
    pattern = cyclic(length=80)
    pwndbg.aglib.regs.write_reg(
        reg_name,
        int.from_bytes(pattern[test_offset : test_offset + ptr_size], pwndbg.aglib.arch.endian),
    )
    out = await ctrl.execute_and_capture(f"cyclic -l ${reg_name}")

    assert out == (
        "Finding cyclic pattern of 4 bytes: b'aaam' (hex: 0x6161616d)\nFound at offset 45\n"
    )


@pwndbg_test
async def test_command_cyclic_address(ctrl: Controller) -> None:
    """
    Tests lookup on a memory address
    """
    from pwnlib.util.cyclic import cyclic

    import pwndbg.aglib
    import pwndbg.aglib.memory

    await ctrl.launch(REFERENCE_BINARY)

    addr = pwndbg.aglib.regs.sp
    test_offset = 48
    pattern = cyclic(length=80)
    pwndbg.aglib.memory.write(addr, pattern)
    out = await ctrl.execute_and_capture(f"cyclic -l '*(unsigned long*){hex(addr + test_offset)}'")

    assert out == (
        "Finding cyclic pattern of 4 bytes: b'maaa' (hex: 0x6d616161)\nFound at offset 48\n"
    )


@pwndbg_test
async def test_command_cyclic_wrong_alphabet(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)

    out = await ctrl.execute_and_capture("cyclic -l 1234")
    assert out == (
        "Finding cyclic pattern of 4 bytes: b'\\xd2\\x04\\x00\\x00' (hex: 0xd2040000)\n"
        "Pattern contains characters not present in the alphabet\n"
    )


@pwndbg_test
async def test_command_cyclic_wrong_length(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)

    out = await ctrl.execute_and_capture("cyclic -l qwe")
    assert out == (
        "Lookup pattern must be at least 4 bytes (use `-n <length>` to lookup pattern of different length)\n"
    )
