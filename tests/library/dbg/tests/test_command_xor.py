from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.out")


@pwndbg_test
async def test_command_xor_with_dbg_execute(ctrl: Controller) -> None:
    """
    Tests simple xoring
    """
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs

    await ctrl.launch(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.rsp
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    await ctrl.execute("xor $rsp ' ' 4")
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"AAAAaaaa"


@pwndbg_test
async def test_command_xor_with_int(ctrl: Controller) -> None:
    """
    Tests simple xoring
    """
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs

    await ctrl.launch(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.rsp
    assert isinstance(before, int)
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    await ctrl.execute(f"xor {before} ' ' 4")
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"AAAAaaaa"


@pwndbg_test
async def test_command_xor_with_hex(ctrl: Controller) -> None:
    """
    Tests simple xoring
    """
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs

    await ctrl.launch(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.rsp
    before_hex = hex(before)
    assert isinstance(before_hex, str)
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    await ctrl.execute(f"xor {before_hex} ' ' 4")
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"AAAAaaaa"


@pwndbg_test
async def test_command_memfrob(ctrl: Controller) -> None:
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs
    from pwndbg.commands.xor import memfrob

    await ctrl.launch(REFERENCE_BINARY)

    before = pwndbg.aglib.regs.rsp
    pwndbg.aglib.memory.write(before, b"aaaaaaaa")
    memfrob(before, 4)
    after = pwndbg.aglib.memory.read(before, 8)
    assert after == b"KKKKaaaa"
