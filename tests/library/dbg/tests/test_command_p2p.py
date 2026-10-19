from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_command_p2p_any(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.memory

    await ctrl.launch(REFERENCE_BINARY)

    sp = pwndbg.aglib.regs.sp
    assert sp is not None
    pwndbg.aglib.memory.write(sp, pwndbg.aglib.arch.pack(sp + 8))

    for name in ("any", "*"):
        out = await ctrl.execute_and_capture(f"p2p {sp:#x}:{sp + 1:#x} {name}")
        assert f"{sp:#x}" in out
        assert "Traceback" not in out
