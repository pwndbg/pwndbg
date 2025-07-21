from __future__ import annotations

from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.out")


@pwndbg_test
async def test_command_cyclic_value(ctrl: Controller) -> None:
    """
    Tests lookup on a constant value
    """
    from pwnlib.util.cyclic import cyclic

    import pwndbg.aglib.arch

    await ctrl.launch(REFERENCE_BINARY)

    ptr_size = pwndbg.aglib.arch.ptrsize
    test_offset = 37
    pattern = cyclic(length=80, n=ptr_size)
    val = int.from_bytes(pattern[test_offset : test_offset + ptr_size], pwndbg.aglib.arch.endian)
    out = await ctrl.execute_and_capture(f"cyclic -l {hex(val)}")

    assert out == (
        "Finding cyclic pattern of 8 bytes: b'aaafaaaa' (hex: 0x6161616661616161)\n"
        "Found at offset 37\n"
    )


@pwndbg_test
async def test_command_cyclic_register(ctrl: Controller) -> None:
    """
    Tests lookup on a register
    """
    from pwnlib.util.cyclic import cyclic

    import pwndbg.aglib.arch
    import pwndbg.aglib.regs

    await ctrl.launch(REFERENCE_BINARY)

    ptr_size = pwndbg.aglib.arch.ptrsize
    test_offset = 45
    pattern = cyclic(length=80, n=ptr_size)
    pwndbg.aglib.regs.rdi = int.from_bytes(
        pattern[test_offset : test_offset + ptr_size], pwndbg.aglib.arch.endian
    )
    out = await ctrl.execute_and_capture("cyclic -l $rdi")

    assert out == (
        "Finding cyclic pattern of 8 bytes: b'aaagaaaa' (hex: 0x6161616761616161)\n"
        "Found at offset 45\n"
    )


@pwndbg_test
async def test_command_cyclic_address(ctrl: Controller) -> None:
    """
    Tests lookup on a memory address
    """
    from pwnlib.util.cyclic import cyclic

    import pwndbg.aglib.arch
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs

    await ctrl.launch(REFERENCE_BINARY)

    addr = pwndbg.aglib.regs.rsp
    ptr_size = pwndbg.aglib.arch.ptrsize
    test_offset = 48
    pattern = cyclic(length=80, n=ptr_size)
    pwndbg.aglib.memory.write(addr, pattern)
    out = await ctrl.execute_and_capture(f"cyclic -l '*(unsigned long*){hex(addr + test_offset)}'")

    assert out == (
        "Finding cyclic pattern of 8 bytes: b'gaaaaaaa' (hex: 0x6761616161616161)\n"
        "Found at offset 48\n"
    )


@pwndbg_test
async def test_command_cyclic_wrong_alphabet(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)

    out = await ctrl.execute_and_capture("cyclic -l 1234")
    assert out == (
        "Finding cyclic pattern of 8 bytes: b'\\xd2\\x04\\x00\\x00\\x00\\x00\\x00\\x00' (hex: 0xd204000000000000)\n"
        "Pattern contains characters not present in the alphabet\n"
    )


@pwndbg_test
async def test_command_cyclic_wrong_length(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)

    out = await ctrl.execute_and_capture("cyclic -l qwerty")
    assert out == (
        "Lookup pattern must be 8 bytes (use `-n <length>` to lookup pattern of different length)\n"
    )
