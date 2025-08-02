from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

SMALL_BINARY = get_binary("crash_simple.out.hardcoded")


@pwndbg_test
async def test_mprotect_executes_properly(ctrl: Controller) -> None:
    """
    Tests the mprotect command
    """
    import pwndbg.aglib.regs
    import pwndbg.aglib.vmmap

    await ctrl.launch(SMALL_BINARY)

    pc = pwndbg.aglib.regs.pc

    # Check if we can use mprotect with address provided as value
    # and to set page permissions to RWX
    await ctrl.execute(f"mprotect {pc} 4096 PROT_EXEC|PROT_READ|PROT_WRITE")
    vm = pwndbg.aglib.vmmap.find(pc)
    assert vm.read and vm.write and vm.execute

    # Check if we can use mprotect with address provided as register
    # and to set page permissions back to RX
    await ctrl.execute("mprotect $pc 0x1000 PROT_EXEC|PROT_READ")
    vm = pwndbg.aglib.vmmap.find(pc)
    assert vm.read and vm.execute and not vm.write
