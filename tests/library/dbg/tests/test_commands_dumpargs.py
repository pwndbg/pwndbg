from __future__ import annotations

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import pwndbg_test

MMAP_GAPS_BINARY = get_binary("mmap_gaps.out")


@pwndbg_test
async def test_dump_mmap_args(ctrl: Controller):
    """
    Tests dumpargs command on an xmmap call
    """

    await ctrl.launch(MMAP_GAPS_BINARY)

    # Run until main
    break_at_sym("main")
    await ctrl.cont()

    # Stop on xmmap(...)
    await ctrl.execute("nextcall")
    # Step into the xmmap(...) call
    await ctrl.step_instruction()
    # Stop on mmap(...)
    await ctrl.execute("nextcall")

    out = (await ctrl.execute_and_capture("dumpargs")).splitlines()
    assert len(out) == 6
    assert out[0] == "        addr:      0xcafe0000"
    assert out[1] == "        len:       0x1000"
    assert out[2] == "        prot:      1"
    assert out[3] == "        flags:     0x32 (MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED)"
    assert out[4] == "        fd:        0xffffffff"
    assert out[5] == "        offset:    0"
