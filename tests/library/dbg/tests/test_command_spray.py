from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_command_spray_value(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.memory

    await ctrl.launch(REFERENCE_BINARY)

    sp = pwndbg.aglib.regs.sp
    assert sp is not None

    # Shorter than, equal to, and not a multiple of the value length
    for length, expected in ((2, b"AB"), (4, b"ABCD"), (6, b"ABCDAB")):
        pwndbg.aglib.memory.write(sp, b"\x00" * 8)
        await ctrl.execute(f"spray {sp} {length} --value ABCD")
        assert pwndbg.aglib.memory.read(sp, 8) == expected.ljust(8, b"\x00")
