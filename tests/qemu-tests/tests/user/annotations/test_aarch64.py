from __future__ import annotations

import pwndbg.gdblib.disasm
import tests
from pwndbg.lib import cache
import gdb

from capstone.arm64_const import ARM64_INS_BL

AARCH64_GRACEFUL_EXIT = """
mov x0, 0
mov x8, 93
svc 0
"""

SIMPLE_FUNCTION = f"""

bl my_function
b end

my_function:
    ret

end:
{AARCH64_GRACEFUL_EXIT}
"""

def test_compile_and_run(compile_and_run):
    compile_and_run(SIMPLE_FUNCTION,"aarch64")

    # TODO: cleaner API to get and enhance one instruction WITH emulation
    instruction = pwndbg.gdblib.disasm.near(pwndbg.gdblib.regs.pc)[0][0]

    # Some random tests
    assert instruction.id == ARM64_INS_BL
    assert instruction.call_like == True
    assert instruction.is_unconditional_jump == True
    assert instruction.target_string == "my_function"

    gdb.execute(f"si")
    gdb.execute(f"stepuntilasm svc")

    instruction = pwndbg.gdblib.disasm.near(pwndbg.gdblib.regs.pc,show_prev_insns=False)[0][0]

    print(instruction)

    assert instruction.syscall == 93
    assert instruction.syscall_name == "exit"








